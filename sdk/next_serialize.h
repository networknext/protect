/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#include "next_util.h"

#include <string.h>
#include <math.h>

namespace next 
{
    #if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
    #define _CRT_SECURE_NO_WARNINGS
    #endif

    #ifdef _MSC_VER
    #pragma warning( disable : 4127 )
    #pragma warning( disable : 4244 )
    #endif // #ifdef _MSC_VER

    /**
        Bitpacks unsigned integer values to a buffer.
        Integer bit values are written to a 64 bit scratch value from right to left.
        Once the low 32 bits of the scratch is filled with bits it is flushed to memory as a dword and the scratch value is shifted right by 32.
        The bit stream is written to memory in little endian order, which is considered network byte order for this library.
        @see BitReader
     */

    // todo
    #define platform_restrict __restrict

    class BitWriter
    {
    public:

        BitWriter()
        {
            memset( (void*) this, 0, sizeof(BitWriter) );
        }

        void Initialize( void * platform_restrict data, int bytes )
        {
            next_assert( data );
            next_assert( ( bytes % 4 ) == 0 );
            m_data = (uint32_t*) data;
            m_numWords = bytes / 4;
            m_numBits = m_numWords * 32;
            m_bitsWritten = 0;
            m_wordIndex = 0;
            m_scratch = 0;
            m_scratchBits = 0;
        }

        /**
            Bit writer constructor.
            Creates a bit writer object to write to the specified buffer.
            @param data The pointer to the buffer to fill with bitpacked data.
            @param bytes The size of the buffer in bytes. Must be a multiple of 4, because the bitpacker reads and writes memory as dwords, not bytes.
         */

        BitWriter( void * platform_restrict data, int bytes ) : m_data( (uint32_t*) data ), m_numWords( bytes / 4 )
        {
            next_assert( data );
            next_assert( ( bytes % 4 ) == 0 );
            m_numBits = m_numWords * 32;
            m_bitsWritten = 0;
            m_wordIndex = 0;
            m_scratch = 0;
            m_scratchBits = 0;
        }

        /**
            Write bits to the buffer.
            Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
            A boolean value writes just 1 bit to the buffer, a value in range [0,31] can be written with just 5 bits and so on.
            IMPORTANT: When you have finished writing to your buffer, take care to call BitWrite::FlushBits, otherwise the last dword of data will not get flushed to memory!
            @param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
            @param bits The number of bits to encode in [1,32].
            @see BitReader::ReadBits
         */

        void WriteBits( uint32_t value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            next_assert( m_bitsWritten + bits <= m_numBits );
            next_assert( uint64_t( value ) <= ( ( 1ULL << bits ) - 1 ) );

            m_scratch |= uint64_t( value ) << m_scratchBits;

            m_scratchBits += bits;

            if ( m_scratchBits >= 32 )
            {
                next_assert( m_wordIndex < m_numWords );
                m_data[m_wordIndex] = host_to_network( uint32_t( m_scratch & 0xFFFFFFFF ) );
                m_scratch >>= 32;
                m_scratchBits -= 32;
                m_wordIndex++;
            }

            m_bitsWritten += bits;
        }

        /**
            Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
            This is useful if you want to write some data to a packet that should be byte aligned. For example, an array of bytes, or a string.
            IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
            @see BitReader::ReadAlign
         */

        void WriteAlign()
        {
            const int remainderBits = m_bitsWritten % 8;

            if ( remainderBits != 0 )
            {
                uint32_t zero = 0;
                WriteBits( zero, 8 - remainderBits );
                next_assert( ( m_bitsWritten % 8 ) == 0 );
            }
        }

        /**
            Write an array of bytes to the bit stream.
            Use this when you have to copy a large block of data into your bitstream.
            Faster than just writing each byte to the bit stream via BitWriter::WriteBits( value, 8 ), because it aligns to byte index and copies into the buffer without bitpacking.
            @param data The byte array data to write to the bit stream.
            @param bytes The number of bytes to write.
            @see BitReader::ReadBytes
         */

        void WriteBytes( const uint8_t * platform_restrict data, int bytes )
        {
            next_assert( GetAlignBits() == 0 );
            next_assert( m_bitsWritten + bytes * 8 <= m_numBits );
            next_assert( ( m_bitsWritten % 32 ) == 0 || ( m_bitsWritten % 32 ) == 8 || ( m_bitsWritten % 32 ) == 16 || ( m_bitsWritten % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsWritten % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                WriteBits( data[i], 8 );
            if ( headBytes == bytes )
                return;

            FlushBits();

            next_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                next_assert( ( m_bitsWritten % 32 ) == 0 );
                memcpy( (char*) &m_data[m_wordIndex], data + headBytes, numWords * 4 );
                m_bitsWritten += numWords * 32;
                m_wordIndex += numWords;
                m_scratch = 0;
            }

            next_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            next_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                WriteBits( data[tailStart+i], 8 );

            next_assert( GetAlignBits() == 0 );

            next_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        /**
            Flush any remaining bits to memory.
            Call this once after you've finished writing bits to flush the last dword of scratch to memory!
            @see BitWriter::WriteBits
         */

        void FlushBits()
        {
            if ( m_scratchBits != 0 )
            {
                next_assert( m_scratchBits <= 32 );
                next_assert( m_wordIndex < m_numWords );
                m_data[m_wordIndex] = host_to_network( uint32_t( m_scratch & 0xFFFFFFFF ) );
                m_scratch >>= 32;
                m_scratchBits = 0;
                m_wordIndex++;
            }
        }

        /**
            How many align bits would be written, if we were to write an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */

        int GetAlignBits() const
        {
            return ( 8 - ( m_bitsWritten % 8 ) ) % 8;
        }

        /**
            How many bits have we written so far?
            @returns The number of bits written to the bit buffer.
         */

        int GetBitsWritten() const
        {
            return m_bitsWritten;
        }

        /**
            How many bits are still available to write?
            For example, if the buffer size is 4, we have 32 bits available to write, if we have already written 10 bytes then 22 are still available to write.
            @returns The number of bits available to write.
         */

        int GetBitsAvailable() const
        {
            return m_numBits - m_bitsWritten;
        }

        /**
            Get a pointer to the data written by the bit writer.
            Corresponds to the data block passed in to the constructor.
            @returns Pointer to the data written by the bit writer.
         */

        uint8_t * GetData() const
        {
            return (uint8_t*) m_data;
        }

        /**
            The number of bytes flushed to memory.
            This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
            The returned value is not always a multiple of 4, even though we flush dwords to memory. You won't miss any data in this case because the order of bits written is designed to work with the little endian memory layout.
            IMPORTANT: Make sure you call BitWriter::FlushBits before calling this method, otherwise you risk missing the last dword of data.
         */

        int GetBytesWritten() const
        {
            return ( m_bitsWritten + 7 ) / 8;
        }

    private:

        uint32_t * m_data;              ///< The buffer we are writing to, as a uint32_t * because we're writing dwords at a time.
        uint64_t m_scratch;             ///< The scratch value where we write bits to (right to left). 64 bit for overflow. Once # of bits in scratch is >= 32, the low 32 bits are flushed to memory.
        int m_numBits;                  ///< The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8. Note that the buffer size must always be a multiple of 4.
        int m_numWords;                 ///< The number of words in the buffer. This is equivalent to the size of the buffer in bytes divided by 4. Note that the buffer size must always be a multiple of 4.
        int m_bitsWritten;              ///< The number of bits written so far.
        int m_wordIndex;                ///< The current word index. The next word flushed to memory will be at this index in m_data.
        int m_scratchBits;              ///< The number of bits in scratch. When this is >= 32, the low 32 bits of scratch is flushed to memory as a dword and scratch is shifted right by 32.
    };

    /**
        Reads bit packed integer values from a buffer.
        Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
        Implementation: 32 bit dwords are read in from memory to the high bits of a scratch value as required. The user reads off bit values from the scratch value from the right, after which the scratch value is shifted by the same number of bits.
     */

    class BitReader
    {
    public:

        BitReader()
        {
            m_data = NULL;
            m_numBytes = 0;
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        void Initialize( const void * platform_restrict data, int bytes )
        {
            next_assert( data );
            m_data = (const uint32_t*) data;
            m_numBytes = bytes;
    #ifdef SERIALIZE_DEBUG
            m_numWords = ( bytes + 3 ) / 4;
    #endif // #ifdef SERIALIZE_DEBUG
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;            
        }

        /**
            Bit reader constructor.
            Non-multiples of four buffer sizes are supported, as this naturally tends to occur when packets are read from the network.
            However, actual buffer allocated for the packet data must round up at least to the next 4 bytes in memory, because the bit reader reads dwords from memory not bytes.
            @param data Pointer to the bitpacked data to read.
            @param bytes The number of bytes of bitpacked data to read.
            @see BitWriter
         */

    #ifdef SERIALIZE_DEBUG
        BitReader( const void * platform_restrict data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes ), m_numWords( ( bytes + 3 ) / 4 )
    #else // #ifdef SERIALIZE_DEBUG
        BitReader( const void * platform_restrict data, int bytes ) : m_data( (const uint32_t*) data ), m_numBytes( bytes )
    #endif // #ifdef SERIALIZE_DEBUG
        {
            next_assert( data );
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        /**
            Would the bit reader would read past the end of the buffer if it read this many bits?
            @param bits The number of bits that would be read.
            @returns True if reading the number of bits would read past the end of the buffer.
         */

        bool WouldReadPastEnd( int bits ) const
        {
            return m_bitsRead + bits > m_numBits;
        }

        /**
            Read bits from the bit buffer.
            This function will assert in debug builds if this read would read past the end of the buffer.
            In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
            @param bits The number of bits to read in [1,32].
            @returns The integer value read in range [0,(1<<bits)-1].
            @see BitReader::WouldReadPastEnd
            @see BitWriter::WriteBits
         */

        uint32_t ReadBits( int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            next_assert( m_bitsRead + bits <= m_numBits );

            m_bitsRead += bits;

            next_assert( m_scratchBits >= 0 && m_scratchBits <= 64 );

            if ( m_scratchBits < bits )
            {
    #ifdef SERIALIZE_DEBUG
                next_assert( m_wordIndex < m_numWords );
    #endif // SERIALIZE_DEBUG
                m_scratch |= uint64_t( network_to_host( m_data[m_wordIndex] ) ) << m_scratchBits;
                m_scratchBits += 32;
                m_wordIndex++;
            }

            next_assert( m_scratchBits >= bits );

            const uint32_t output = m_scratch & ( (uint64_t(1)<<bits) - 1 );

            m_scratch >>= bits;
            m_scratchBits -= bits;

            return output;
        }

        /**
            Read an align.
            Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
            This makes sure we skip ahead to the next aligned byte index. As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
            This will typically abort packet read. Just another safety measure...
            @returns True if we successfully read an align and skipped ahead past zero pad, false otherwise (probably means, no align was written to the stream).
            @see BitWriter::WriteAlign
         */

        bool ReadAlign()
        {
            const int remainderBits = m_bitsRead % 8;
            if ( remainderBits != 0 )
            {
                uint32_t value = ReadBits( 8 - remainderBits );
                next_assert( m_bitsRead % 8 == 0 );
                if ( value != 0 )
                    return false;
            }
            return true;
        }

        /**
            Read bytes from the bitpacked data.
            @see BitWriter::WriteBytes
         */

        void ReadBytes( uint8_t * platform_restrict data, int bytes )
        {
            next_assert( GetAlignBits() == 0 );
            next_assert( m_bitsRead + bytes * 8 <= m_numBits );
            next_assert( ( m_bitsRead % 32 ) == 0 || ( m_bitsRead % 32 ) == 8 || ( m_bitsRead % 32 ) == 16 || ( m_bitsRead % 32 ) == 24 );

            int headBytes = ( 4 - ( m_bitsRead % 32 ) / 8 ) % 4;
            if ( headBytes > bytes )
                headBytes = bytes;
            for ( int i = 0; i < headBytes; ++i )
                data[i] = (uint8_t) ReadBits( 8 );
            if ( headBytes == bytes )
                return;

            next_assert( GetAlignBits() == 0 );

            int numWords = ( bytes - headBytes ) / 4;
            if ( numWords > 0 )
            {
                next_assert( ( m_bitsRead % 32 ) == 0 );
                memcpy( (char*) data + headBytes, &m_data[m_wordIndex], numWords * 4 );
                m_bitsRead += numWords * 32;
                m_wordIndex += numWords;
                m_scratchBits = 0;
            }

            next_assert( GetAlignBits() == 0 );

            int tailStart = headBytes + numWords * 4;
            int tailBytes = bytes - tailStart;
            next_assert( tailBytes >= 0 && tailBytes < 4 );
            for ( int i = 0; i < tailBytes; ++i )
                data[tailStart+i] = (uint8_t) ReadBits( 8 );

            next_assert( GetAlignBits() == 0 );

            next_assert( headBytes + numWords * 4 + tailBytes == bytes );
        }

        /**
            How many align bits would be read, if we were to read an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */

        int GetAlignBits() const
        {
            return ( 8 - m_bitsRead % 8 ) % 8;
        }

        /**
            How many bits have we read so far?
            @returns The number of bits read from the bit buffer so far.
         */

        int GetBitsRead() const
        {
            return m_bitsRead;
        }

        /**
            How many bits are still available to read?
            For example, if the buffer size is 4, we have 32 bits available to read, if we have already written 10 bytes then 22 are still available.
            @returns The number of bits available to read.
         */

        int GetBitsRemaining() const
        {
            return m_numBits - m_bitsRead;
        }

        /**
            Get a pointer to the data behind by the bit reader.
            Corresponds to the data block passed in to the constructor.
            @returns Pointer to the data behind the bit reader.
         */

        uint8_t * GetData() const
        {
            return (uint8_t*) m_data;
        }

    private:

        const uint32_t * platform_restrict m_data;         ///< The bitpacked data we're reading as a dword array.
        uint64_t m_scratch;                                 ///< The scratch value. New data is read in 32 bits at a top to the left of this buffer, and data is read off to the right.
        int m_numBits;                                      ///< Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually m_numBytes * 8.
        int m_numBytes;                                     ///< Number of bytes to read in the buffer. We know this, and this is the non-rounded up version.
    #ifdef SERIALIZE_DEBUG
        int m_numWords;                                     ///< Number of words to read in the buffer. This is rounded up to the next word if necessary.
    #endif // #ifdef SERIALIZE_DEBUG
        int m_bitsRead;                                     ///< Number of bits read from the buffer so far.
        int m_scratchBits;                                  ///< Number of bits currently in the scratch value. If the user wants to read more bits than this, we have to go fetch another dword from memory.
        int m_wordIndex;                                    ///< Index of the next word to read from memory.
    };

    /**
        Functionality common to all stream classes.
     */

    class BaseStream
    {
    public:

        /**
            Base stream constructor.
         */

        explicit BaseStream() : m_allocator( NULL ) {}

        /**
            Set an allocator pointer on the stream.
            This can be helpful if you want to perform allocations within serialize functions.
         */

        void SetAllocator( void * allocator )
        {
            m_allocator = allocator;
        }

        /**
            Get the allocator pointer set on the stream.

            @returns The allocator pointer. May be NULL.
         */

        void * GetAllocator() const
        {
            return m_allocator;
        }

    private:

        void * m_allocator;                         ///< The allocator pointer set on the stream. May be NULL.
    };

    /**
        Stream class for writing bitpacked data.
        This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are writing to a stream by calling Stream::IsWriting inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
        @see BitWriter
     */

    class WriteStream : public BaseStream
    {
    public:

        enum { IsWriting = 1 };
        enum { IsReading = 0 };

        WriteStream() : m_writer() {}

        void Initialize( uint8_t * buffer, int bytes )
        {
            m_writer.Initialize( buffer, bytes );
        }

        /**
            Write stream constructor.
            @param buffer The buffer to write to.
            @param bytes The number of bytes in the buffer. Must be a multiple of four.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */

        WriteStream( uint8_t * buffer, int bytes ) : m_writer( buffer, bytes ) {}

        /**
            Serialize an integer (write).
            @param value The integer value in [min,max].
            @param min The minimum value.
            @param max The maximum value.
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */

        bool SerializeInteger( int32_t value, int32_t min, int32_t max )
        {
            next_assert( min < max );
            next_assert( value >= min );
            next_assert( value <= max );
            const int bits = bits_required( min, max );
            uint32_t unsigned_value = value - min;
            m_writer.WriteBits( unsigned_value, bits );
            return true;
        }

        /**
            Serialize a number of bits (write).
            @param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
            @param bits The number of bits to write in [1,32].
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBits( uint32_t value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            m_writer.WriteBits( value, bits );
            return true;
        }

        /**
            Serialize an array of bytes (write).
            @param data Array of bytes to be written.
            @param bytes The number of bytes to write.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBytes( const uint8_t * data, int bytes )
        {
            next_assert( data );
            next_assert( bytes >= 0 );
            SerializeAlign();
            m_writer.WriteBytes( data, bytes );
            return true;
        }

        /**
            Serialize an align (write).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeAlign()
        {
            m_writer.WriteAlign();
            return true;
        }

        /**
            If we were to write an align right now, how many bits would be required?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */

        int GetAlignBits() const
        {
            return m_writer.GetAlignBits();
        }

        /**
            Flush the stream to memory after you finish writing.
            Always call this after you finish writing and before you call WriteStream::GetData, or you'll potentially truncate the last dword of data you wrote.
            @see BitWriter::FlushBits
         */

        void Flush()
        {
            m_writer.FlushBits();
        }

        /**
            Get a pointer to the data written by the stream.
            IMPORTANT: Call WriteStream::Flush before you call this function!
            @returns A pointer to the data written by the stream
         */

        uint8_t * GetData() const
        {
            return m_writer.GetData();
        }

        /**
            How many bytes have been written so far?
            @returns Number of bytes written. This is effectively the packet size.
         */

        int GetBytesProcessed() const
        {
            return m_writer.GetBytesWritten();
        }

        /**
            Get number of bits written so far.
            @returns Number of bits written.
         */

        int GetBitsProcessed() const
        {
            return m_writer.GetBitsWritten();
        }

        /**
            Get number of bits available for writing.
            @returns Number of bits left in the stream.
         */

        int GetBitsAvailable() const
        {
            return m_writer.GetBitsAvailable();
        }

    private:

        BitWriter m_writer;                 ///< The bit writer used for all bitpacked write operations.
    };

    /**
        Stream class for reading bitpacked data.
        This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are reading from a stream by calling Stream::IsReading inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
        @see BitReader
     */

    class ReadStream : public BaseStream
    {
    public:

        enum { IsWriting = 0 };
        enum { IsReading = 1 };

        ReadStream()
        {
            // ...
        }

        void Initialize( const uint8_t * buffer, int bytes )
        {
            m_reader.Initialize( buffer, bytes );
        }

        /**
            Read stream constructor.
            @param buffer The buffer to read from.
            @param bytes The number of bytes in the buffer. May be a non-multiple of four, however if it is, the underlying buffer allocated should be large enough to read the any remainder bytes as a dword.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */

        ReadStream( const uint8_t * buffer, int bytes ) : m_reader( buffer, bytes ) {}

        /**
            Serialize an integer (read).
            @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
            @param min The minimum allowed value.
            @param max The maximum allowed value.
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */

        bool SerializeInteger( int32_t & value, int32_t min, int32_t max )
        {
            next_assert( min < max );
            const int bits = bits_required( min, max );
            if ( m_reader.WouldReadPastEnd( bits ) )
                return false;
            uint32_t unsigned_value = m_reader.ReadBits( bits );
            value = (int32_t) unsigned_value + min;
            return true;
        }

        /**
            Serialize a number of bits (read).
            @param value The integer value read is stored here. Will be in range [0,(1<<bits)-1].
            @param bits The number of bits to read in [1,32].
            @returns Returns true if the serialize read succeeded, false otherwise.
         */

        bool SerializeBits( uint32_t & value, int bits )
        {
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            if ( m_reader.WouldReadPastEnd( bits ) )
                return false;
            uint32_t read_value = m_reader.ReadBits( bits );
            value = read_value;
            return true;
        }

        /**
            Serialize an array of bytes (read).
            @param data Array of bytes to read.
            @param bytes The number of bytes to read.
            @returns Returns true if the serialize read succeeded. False otherwise.
         */

        bool SerializeBytes( uint8_t * data, int bytes )
        {
            if ( !SerializeAlign() )
                return false;
            if ( m_reader.WouldReadPastEnd( bytes * 8 ) )
                return false;
            m_reader.ReadBytes( data, bytes );
            return true;
        }

        /**
            Serialize an align (read).
            @returns Returns true if the serialize read succeeded. False otherwise.
         */

        bool SerializeAlign()
        {
            const int alignBits = m_reader.GetAlignBits();
            if ( m_reader.WouldReadPastEnd( alignBits ) )
                return false;
            if ( !m_reader.ReadAlign() )
                return false;
            return true;
        }

        /**
            If we were to read an align right now, how many bits would we need to read?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */

        int GetAlignBits() const
        {
            return m_reader.GetAlignBits();
        }

        /**
            Get number of bits read so far.
            @returns Number of bits read.
         */

        int GetBitsProcessed() const
        {
            return m_reader.GetBitsRead();
        }

        /**
            How many bytes have been read so far?
            @returns Number of bytes read. Effectively this is the number of bits read, rounded up to the next byte where necessary.
         */

        int GetBytesProcessed() const
        {
            return ( m_reader.GetBitsRead() + 7 ) / 8;
        }

        /**
            Get a pointer to the data behind the stream.
            @returns A pointer to the stream data
         */

        uint8_t * GetData() const
        {
            return m_reader.GetData();
        }

    private:

        BitReader m_reader;             ///< The bit reader used for all bitpacked read operations.
    };

    /**
        Stream class for estimating how many bits it would take to serialize something.
        This class acts like a bit writer (IsWriting is 1, IsReading is 0), but instead of writing data, it counts how many bits would be written.
        Note that when the serialization includes alignment to byte (see MeasureStream::SerializeAlign), this is an estimate and not an exact measurement. The estimate is guaranteed to be conservative.
        @see BitWriter
        @see BitReader
     */

    class MeasureStream : public BaseStream
    {
    public:

        enum { IsWriting = 1 };
        enum { IsReading = 0 };

        /**
            Measure stream constructor.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */

        explicit MeasureStream() : m_bitsWritten(0) {}

        /**
            Serialize an integer (measure).
            @param value The integer value to write. Not actually used or checked.
            @param min The minimum value.
            @param max The maximum value.
            @returns Always returns true. All checking is performed by debug asserts only on measure.
         */

        bool SerializeInteger( int32_t value, int32_t min, int32_t max )
        {
            (void) value;
            next_assert( min < max );
            next_assert( value >= min );
            next_assert( value <= max );
            const int bits = bits_required( min, max );
            m_bitsWritten += bits;
            return true;
        }

        /**
            Serialize a number of bits (write).
            @param value The unsigned integer value to serialize. Not actually used or checked.
            @param bits The number of bits to write in [1,32].
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBits( uint32_t value, int bits )
        {
            (void) value;
            next_assert( bits > 0 );
            next_assert( bits <= 32 );
            m_bitsWritten += bits;
            return true;
        }

        /**
            Serialize an array of bytes (measure).
            @param data Array of bytes to 'write'. Not actually used.
            @param bytes The number of bytes to 'write'.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeBytes( const uint8_t * data, int bytes )
        {
            (void) data;
            SerializeAlign();
            m_bitsWritten += bytes * 8;
            return true;
        }

        /**
            Serialize an align (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeAlign()
        {
            const int alignBits = GetAlignBits();
            m_bitsWritten += alignBits;
            return true;
        }

        /**
            If we were to write an align right now, how many bits would be required?
            IMPORTANT: Since the number of bits required for alignment depends on where an object is written in the final bit stream, this measurement is conservative.
            @returns Always returns worst case 7 bits.
         */

        int GetAlignBits() const
        {
            return 7;
        }

        /**
            Serialize a safety check to the stream (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */

        bool SerializeCheck()
        {
    #if SERIALIZE_SERIALIZE_CHECKS
            SerializeAlign();
            m_bitsWritten += 32;
    #endif // #if SERIALIZE_SERIALIZE_CHECKS
            return true;
        }

        /**
            Get number of bits written so far.
            @returns Number of bits written.
         */

        int GetBitsProcessed() const
        {
            return m_bitsWritten;
        }

        /**
            How many bytes have been written so far?
            @returns Number of bytes written.
         */

        int GetBytesProcessed() const
        {
            return ( m_bitsWritten + 7 ) / 8;
        }

    private:

        int m_bitsWritten;              ///< Counts the number of bits written.
    };

    /**
        Serialize integer value (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The integer value to serialize in [min,max].
        @param min The minimum value.
        @param max The maximum value.
     */

    #define serialize_int( stream, value, min, max )                    \
        do                                                              \
        {                                                               \
            next_assert( min < max );                                   \
            int32_t int32_value = 0;                                    \
            if ( Stream::IsWriting )                                    \
            {                                                           \
                next_assert( int64_t(value) >= int64_t(min) );          \
                next_assert( int64_t(value) <= int64_t(max) );          \
                int32_value = (int32_t) value;                          \
            }                                                           \
            if ( !stream.SerializeInteger( int32_value, min, max ) )    \
            {                                                           \
                return false;                                           \
            }                                                           \
            if ( Stream::IsReading )                                    \
            {                                                           \
                value = int32_value;                                    \
                if ( int64_t(value) < int64_t(min) ||                   \
                     int64_t(value) > int64_t(max) )                    \
                {                                                       \
                    return false;                                       \
                }                                                       \
            }                                                           \
        } while (0)

    /**
        Serialize bits to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The unsigned integer value to serialize.
        @param bits The number of bits to serialize in [1,32].
     */

    #define serialize_bits( stream, value, bits )                       \
        do                                                              \
        {                                                               \
            next_assert( bits > 0 );                                    \
            next_assert( bits <= 64 );                                  \
            if ( bits <= 32 )                                           \
            {                                                           \
                uint32_t uint32_value = 0;                              \
                if ( Stream::IsWriting )                                \
                {                                                       \
                    uint32_value = (uint32_t) value;                    \
                }                                                       \
                if ( !stream.SerializeBits( uint32_value, bits ) )      \
                {                                                       \
                    return false;                                       \
                }                                                       \
                if ( Stream::IsReading )                                \
                {                                                       \
                    value = uint32_value;                               \
                }                                                       \
            }                                                           \
            else                                                        \
            {                                                           \
                uint32_t hi = 0, lo = 0;                                \
                if ( Stream::IsWriting )                                \
                {                                                       \
                    lo = uint32_t( uint64_t(value) & 0xFFFFFFFF );      \
                    hi = uint32_t( uint64_t(value) >> 32 );             \
                }                                                       \
                if ( !stream.SerializeBits( lo, 32 ) )                  \
                {                                                       \
                    return false;                                       \
                }                                                       \
                if ( !stream.SerializeBits( hi, bits - 32 ) )           \
                {                                                       \
                    return false;                                       \
                }                                                       \
                if ( Stream::IsReading )                                \
                {                                                       \
                    value = ( uint64_t(hi) << 32 ) | lo;                \
                }                                                       \
            }                                                           \
        } while (0)


    /**
        Serialize a boolean value to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The boolean value to serialize.
     */

    #define serialize_bool( stream, value )                             \
        do                                                              \
        {                                                               \
            uint32_t uint32_bool_value = 0;                             \
            if ( Stream::IsWriting )                                    \
            {                                                           \
                uint32_bool_value = value ? 1 : 0;                      \
            }                                                           \
            serialize_bits( stream, uint32_bool_value, 1 );             \
            if ( Stream::IsReading )                                    \
            {                                                           \
                value = uint32_bool_value ? true : false;               \
            }                                                           \
        } while (0)

    template <typename Stream> bool serialize_float_internal( Stream & stream, float & value )
    {
        uint32_t int_value;
        if ( Stream::IsWriting )
        {
            memcpy( (char*) &int_value, &value, 4 );
        }
        bool result = stream.SerializeBits( int_value, 32 );
        if ( Stream::IsReading )
        {
            memcpy( (char*) &value, &int_value, 4 );
        }
        return result;
    }

    /**
        Serialize floating point value (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The float value to serialize.
     */

    #define serialize_float( stream, value )                                        \
        do                                                                          \
        {                                                                           \
            if ( !serialize_float_internal( stream, value ) )                       \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    template <typename Stream> bool serialize_compressed_float_internal( Stream & stream, float & value, float min, float max, float res )
    {
        const float delta = max - min;

        const float values = delta / res;

        const uint32_t maxIntegerValue = (uint32_t) ceil(values);

        const int bits = bits_required( 0, maxIntegerValue );
        
        uint32_t integerValue = 0;
        
        if ( Stream::IsWriting )
        {
            float normalizedValue = clamp( (value - min) / delta, 0.0f, 1.0f );
            integerValue = (uint32_t) floor( normalizedValue * maxIntegerValue + 0.5f );
        }

        if ( !stream.SerializeBits( integerValue, bits ) )
        {
            return false;
        }
        
        if ( Stream::IsReading )
        {
            const float normalizedValue = integerValue / float(maxIntegerValue);
            value = normalizedValue * delta + min;
        }
        
        return true;
    }

    /**
        Serialize compressed floating point value (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The float value to serialize.
     */

    #define serialize_compressed_float(stream, value, min, max, res)                                \
    do                                                                                              \
    {                                                                                               \
        if ( !serialize_compressed_float_internal( stream, value, min, max, res) )                  \
        {                                                                                           \
            return false;                                                                           \
        }                                                                                           \
    } while (0)

    template <typename Stream> bool serialize_double_internal( Stream & stream, double & value )
    {
        union DoubleInt
        {
            double double_value;
            uint64_t int_value;
        };
        DoubleInt tmp = { 0 };
        if ( Stream::IsWriting )
        {
            tmp.double_value = value;
        }
        serialize_bits( stream, tmp.int_value, 64 );
        if ( Stream::IsReading )
        {
            value = tmp.double_value;
        }
        return true;
    }

    /**
        Serialize double precision floating point value to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The double precision floating point value to serialize.
     */

    #define serialize_double( stream, value )                                       \
        do                                                                          \
        {                                                                           \
            if ( !serialize_double_internal( stream, value ) )                      \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    template <typename Stream> bool serialize_bytes_internal( Stream & stream, uint8_t * data, int bytes )
    {
        return stream.SerializeBytes( data, bytes );
    }

    /**
        Serialize unsigned 8 bit integer (read/write/measure).
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The unsigned 16 bit integer value.
     */

    #define serialize_uint8( stream, value ) serialize_bits( stream, value, 8 );

    /**
        Serialize unsigned 16 bit integer (read/write/measure).
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The unsigned 16 bit integer value.
     */

    #define serialize_uint16( stream, value ) serialize_bits( stream, value, 16 );

    /**
        Serialize unsigned 32 bit integer (read/write/measure).
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The unsigned 32 bit integer value.
     */

    #define serialize_uint32( stream, value ) serialize_bits( stream, value, 32 );

    /**
        Serialize unsigned 64 bit integer (read/write/measure).
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param value The unsigned 64 bit integer value.
     */

    #define serialize_uint64( stream, value ) serialize_bits( stream, value, 64 );

    /**
        Serialize an array of bytes to the stream (read/write/measure).
        This is a helper macro to make unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param data Pointer to the data to be serialized.
        @param bytes The number of bytes to serialize.
     */

    #define serialize_bytes( stream, data, bytes )                                  \
        do                                                                          \
        {                                                                           \
            if ( !serialize_bytes_internal( stream, data, bytes ) )                 \
            {                                                                       \
                return false;                                                       \
            }                                                                       \
        } while (0)

    template <typename Stream> bool serialize_string_internal( Stream & stream, char * string, int buffer_size )
    {
        int length = 0;
        if ( Stream::IsWriting )
        {
            length = (int) strlen( string );
            next_assert( length < buffer_size );
        }
        serialize_int( stream, length, 0, buffer_size - 1 );
        serialize_bytes( stream, (uint8_t*)string, length );
        if ( Stream::IsReading )
        {
            string[length] = '\0';
        }
        return true;
    }

    /**
        Serialize a string to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param string The string to serialize write/measure. Pointer to buffer to be filled on read.
        @param buffer_size The size of the string buffer. String with terminating null character must fit into this buffer.
     */

    #define serialize_string( stream, string, buffer_size )                                 \
        do                                                                                  \
        {                                                                                   \
            if ( !serialize_string_internal( stream, string, buffer_size ) )                \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    /**
        Serialize an alignment to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
     */

    #define serialize_align( stream )                                                       \
        do                                                                                  \
        {                                                                                   \
            if ( !stream.SerializeAlign() )                                                 \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    /**
        Serialize an object to the stream (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param object The object to serialize. Must have a serialize method on it.
     */

    #define serialize_object( stream, object )                                              \
        do                                                                                  \
        {                                                                                   \
            if ( !object.Serialize( stream ) )                                              \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        }                                                                                   \
        while(0)

    template <typename Stream, typename T> bool serialize_int_relative_internal( Stream & stream, T previous, T & current )
    {
        uint32_t difference = 0;
        if ( Stream::IsWriting )
        {
            next_assert( previous < current );
            difference = current - previous;
        }

        bool oneBit = false;
        if ( Stream::IsWriting )
        {
            oneBit = difference == 1;
        }
        serialize_bool( stream, oneBit );
        if ( oneBit )
        {
            if ( Stream::IsReading )
            {
                current = previous + 1;
            }
            return true;
        }

        bool twoBits = false;
        if ( Stream::IsWriting )
        {
            twoBits = difference <= 6;
        }
        serialize_bool( stream, twoBits );
        if ( twoBits )
        {
            serialize_int( stream, difference, 2, 6 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool fourBits = false;
        if ( Stream::IsWriting )
        {
            fourBits = difference <= 23;
        }
        serialize_bool( stream, fourBits );
        if ( fourBits )
        {
            serialize_int( stream, difference, 7, 23 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool eightBits = false;
        if ( Stream::IsWriting )
        {
            eightBits = difference <= 280;
        }
        serialize_bool( stream, eightBits );
        if ( eightBits )
        {
            serialize_int( stream, difference, 24, 280 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool twelveBits = false;
        if ( Stream::IsWriting )
        {
            twelveBits = difference <= 4377;
        }
        serialize_bool( stream, twelveBits );
        if ( twelveBits )
        {
            serialize_int( stream, difference, 281, 4377 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        bool sixteenBits = false;
        if ( Stream::IsWriting )
        {
            sixteenBits = difference <= 69914;
        }
        serialize_bool( stream, sixteenBits );
        if ( sixteenBits )
        {
            serialize_int( stream, difference, 4378, 69914 );
            if ( Stream::IsReading )
            {
                current = previous + difference;
            }
            return true;
        }

        uint32_t value = current;
        serialize_bits( stream, value, 32 );
        if ( Stream::IsReading )
        {
            current = value;
        }

        return true;
    }

    /**
        Serialize an integer value relative to another (read/write/measure).
        This is a helper macro to make writing unified serialize functions easier.
        Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
        IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
        @param stream The stream object. May be a read, write or measure stream.
        @param previous The previous integer value.
        @param current The current integer value.
     */

    #define serialize_int_relative( stream, previous, current )                             \
        do                                                                                  \
        {                                                                                   \
            if ( !serialize_int_relative_internal( stream, previous, current ) )            \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    template <typename Stream> bool serialize_ack_relative_internal( Stream & stream, uint16_t sequence, uint16_t & ack )
    {
        int ack_delta = 0;
        bool ack_in_range = false;
        if ( Stream::IsWriting )
        {
            if ( ack < sequence )
            {
                ack_delta = sequence - ack;
            }
            else
            {
                ack_delta = (int)sequence + 65536 - ack;
            }
            next_assert( ack_delta > 0 );
            next_assert( uint16_t( sequence - ack_delta ) == ack );
            ack_in_range = ack_delta <= 64;
        }
        serialize_bool( stream, ack_in_range );
        if ( ack_in_range )
        {
            serialize_int( stream, ack_delta, 1, 64 );
            if ( Stream::IsReading )
            {
                ack = sequence - ack_delta;
            }
        }
        else
        {
            serialize_bits( stream, ack, 16 );
        }
        return true;
    }

    // read macros corresponding to each serialize_*. useful when you want separate read and write functions.

    #define read_bits( stream, value, bits )                                                \
        do                                                                                  \
        {                                                                                   \
            next_assert( bits > 0 );                                                        \
            next_assert( bits <= 64 );                                                      \
            if ( bits <= 32 )                                                               \
            {                                                                               \
                uint32_t uint32_value;                                                      \
                if ( !stream.SerializeBits( uint32_value, bits ) )                          \
                {                                                                           \
                    return false;                                                           \
                }                                                                           \
                value = uint32_value;                                                       \
            }                                                                               \
            else                                                                            \
            {                                                                               \
                uint32_t lo = 0;                                                            \
                uint32_t hi = 0;                                                            \
                if ( !stream.SerializeBits( lo, 32 ) )                                      \
                {                                                                           \
                    return false;                                                           \
                }                                                                           \
                if ( !stream.SerializeBits( hi, bits - 32 ) )                               \
                {                                                                           \
                    return false;                                                           \
                }                                                                           \
                value = ( uint64_t(hi) << 32 ) | lo;                                        \
            }                                                                               \
        } while (0)

    #define read_int( stream, value, min, max )                                             \
        do                                                                                  \
        {                                                                                   \
            next_assert( min < max );                                                       \
            int32_t int32_value = 0;                                                        \
            if ( !stream.SerializeInteger( int32_value, min, max ) )                        \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            value = int32_value;                                                            \
            if ( value < min || value > max )                                               \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    #define read_bool( stream, value )      read_bits( stream, value, 1 )
    #define read_uint8( stream, value )     read_bits( stream, value, 8 )
    #define read_uint16( stream, value )    read_bits( stream, value, 16 )
    #define read_uint32( stream, value )    read_bits( stream, value, 32 )
    #define read_uint64( stream, value )    read_bits( stream, value, 64 )

    #define read_float                  serialize_float
    #define read_double                 serialize_double

    #define read_bytes( stream, data, bytes )                                               \
        do                                                                                  \
        {                                                                                   \
            uint8_t * data_ptr = (uint8_t*) data;                                           \
            if ( !stream.SerializeBytes( data_ptr, bytes ) )                                \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    #define read_string( stream, string, buffer_size )                                      \
        do                                                                                  \
        {                                                                                   \
            char * string_ptr = (char*) string;                                             \
            if ( !serialize_string_internal( stream, string_ptr, buffer_size ) )            \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
        } while (0)

    #define read_align                  serialize_align
    #define read_check                  check
    #define read_object                 serialize_object
    #define read_int_relative           serialize_int_relative

    // write macros corresponding to each serialize_*. useful when you want separate read and write functions.

    #define write_bits( stream, value, bits )                                               \
        do                                                                                  \
        {                                                                                   \
            uint64_t uint64_value = value;                                                  \
            if ( bits <= 32 )                                                               \
            {                                                                               \
                uint32_t uint32_value = (uint32_t) uint64_value;                            \
                stream.SerializeBits( uint32_value, bits );                                 \
            }                                                                               \
            else                                                                            \
            {                                                                               \
                uint32_t lo = uint32_t( uint64_value & 0xFFFFFFFF );                        \
                uint32_t hi = uint32_t( uint64_value >> 32 );                               \
                stream.SerializeBits( lo, 32 );                                             \
                stream.SerializeBits( hi, bits - 32 );                                      \
            }                                                                               \
        } while (0)

    #define write_int( stream, value, min, max )                                            \
        do                                                                                  \
        {                                                                                   \
            next_assert( (int32_t) min < (int32_t) max );                                   \
            next_assert( (int32_t) value >= (int32_t) min );                                \
            next_assert( (int32_t) value <= (int32_t) max );                                \
            int32_t int32_value = (int32_t) value;                                          \
            stream.SerializeInteger( int32_value, min, max );                               \
        } while (0)

    #define write_bool( stream, value )         write_bits( stream, value, 1 )
    #define write_uint8( stream, value )        write_bits( stream, value, 8 )
    #define write_uint16( stream, value )       write_bits( stream, value, 16 )
    #define write_uint32( stream, value )       write_bits( stream, value, 32 )
    #define write_uint64( stream, value )       write_bits( stream, value, 64 )

    #define write_float( stream, value )                                                    \
        do                                                                                  \
        {                                                                                   \
            float float_value = (float) value;                                              \
            uint32_t int_value;                                                             \
            memcpy( (char*) &int_value, &float_value, 4 );                                  \
            stream.SerializeBits( int_value, 32 );                                          \
        } while (0)

    #define write_double( stream, value )                                                   \
        do                                                                                  \
        {                                                                                   \
            double double_value = (double) value;                                           \
            uint64_t int64_value;                                                           \
            memcpy( (char*) &int64_value, &double_value, 8 );                               \
            write_bits( stream, int64_value, 64 );                                          \
        } while (0)

    #define write_bytes( stream, data, bytes )                                              \
        do                                                                                  \
        {                                                                                   \
            const uint8_t * data_ptr = (const uint8_t*) data;                               \
            stream.SerializeBytes( data_ptr, bytes );                                       \
        } while (0)

    #define write_string( stream, string, buffer_size )                                     \
        do                                                                                  \
        {                                                                                   \
            int length = (int) strlen( string );                                            \
            next_assert( length < buffer_size );                                            \
            write_int( stream, length, 0, buffer_size - 1 );                                \
            write_bytes( stream, (uint8_t*)string, length );                                \
        } while (0)

    #define write_align( stream )                                                           \
        do                                                                                  \
        {                                                                                   \
            stream.SerializeAlign();                                                        \
        } while (0)

    #define write_object( stream, object )                                                  \
        do                                                                                  \
        {                                                                                   \
            object.Serialize( stream );                                                     \
        }                                                                                   \
        while(0)

    #define write_int_relative( stream, previous, current )                                 \
        do                                                                                  \
        {                                                                                   \
            int current_value = (int) current;                                              \
            serialize_int_relative_internal( stream, previous, current_value );             \
        } while (0)

    inline void serialize_copy_string( char * dest, const char * source, size_t dest_size )
    {
        next_assert( dest );
        next_assert( source );
        next_assert( dest_size >= 1 );
        memset( dest, 0, dest_size );
        for ( size_t i = 0; i < dest_size - 1; i++ )
        {
            if ( source[i] == '\0' )
                break;
            dest[i] = source[i];
        }
    }
}