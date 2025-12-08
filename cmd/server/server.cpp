/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
#include "next_server_socket.h"
#include "next_platform.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <map>

#define LOAD_TEST 0

#ifdef __linux__
#include <unistd.h>
#endif // #ifdef __linux__

#define NUM_SEND_THREADS 8

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

// ---------------------------------------------------------------------------

#if LOAD_TEST

#if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

#include <pthread.h>

typedef void (*platform_thread_func_t)( void *arg );

class ThreadPool
{
public:

    ThreadPool( int numThreads )
    {
        next_assert( numThreads >= 1 );

        m_startTime = 0.0;
        m_finishTime = 0.0;

        m_stop = false;
        m_maxTasks = numThreads;
        m_numThreads = numThreads;
        m_numTasks = 0;
        m_numWorking = 0;

        m_tasks = (TaskData*) malloc( sizeof(TaskData) * numThreads );
        next_assert( m_tasks );

        pthread_mutex_init( &m_taskMutex, NULL );
        pthread_cond_init( &m_taskCondition, NULL );
        pthread_cond_init( &m_workingCondition, NULL );

#if HIGH_PRIORITY_WORKER_THREADS
        struct sched_param param;
        param.sched_priority = sched_get_priority_max( SCHED_RR );
#endif // #if HIGH_PRIORITY_WORKER_THREADS

        for ( int i = 0; i < numThreads; i++) 
        {
            pthread_t thread;
            pthread_create( &thread, NULL, WorkerThreadFunction, this );
#if HIGH_PRIORITY_WORKER_THREADS
            pthread_setschedparam( thread, SCHED_RR, &param );
#endif // #if HIGH_PRIORITY_WORKER_THREADS
            pthread_detach( thread );
        }
    }

    ~ThreadPool()
    {
        pthread_mutex_lock( &m_taskMutex );

        m_stop = true;

        pthread_cond_broadcast( &m_taskCondition );
        pthread_mutex_unlock( &m_taskMutex );

        Join();

        pthread_mutex_destroy( &m_taskMutex );
        pthread_cond_destroy( &m_taskCondition );
        pthread_cond_destroy( &m_workingCondition );

        free( m_tasks );
        m_tasks = NULL;
    }

    void StartTimer()
    {
        pthread_mutex_lock( &m_taskMutex );
        m_startTime = next_platform_time();
        pthread_mutex_unlock( &m_taskMutex );
    }

    void AddTask( platform_thread_func_t func, void * arg )
    {
        pthread_mutex_lock( &m_taskMutex );
        {
            next_assert( m_numTasks >= 0 );
            next_assert( m_numTasks < m_maxTasks );
            m_tasks[m_numTasks].func = func;
            m_tasks[m_numTasks].arg = arg;
            m_numTasks++;
            pthread_cond_broadcast( &m_taskCondition );
        }
        pthread_mutex_unlock( &m_taskMutex );
    }

    void Join()
    {
        pthread_mutex_lock( &m_taskMutex );
        while (1) 
        {
            if ( m_numTasks > 0 || ( !m_stop && m_numWorking > 0 ) || ( m_stop && m_numThreads != 0 ) ) 
            {
                pthread_cond_wait( &m_workingCondition, &m_taskMutex );
            } 
            else 
            {
                break;
            }
        }
        pthread_mutex_unlock( &m_taskMutex );
    }

    double GetTotalTaskTime()
    {
        pthread_mutex_lock( &m_taskMutex );
        double totalTaskTime = m_finishTime - m_startTime;
        pthread_mutex_unlock( &m_taskMutex );
        return totalTaskTime;
    }

protected:

    static void * WorkerThreadFunction( void * arg )
    {
        ThreadPool * pool = (ThreadPool*) arg;

        while ( true )
        {
            TaskData task;

            pthread_mutex_lock( &pool->m_taskMutex );
            {
                while ( pool->m_numTasks == 0 && !pool->m_stop )
                {
                    pthread_cond_wait( &pool->m_taskCondition, &pool->m_taskMutex );
                }

                if ( pool->m_stop )
                {
                    next_assert( pool->m_numThreads > 0 );
                    pool->m_numThreads--;
                    pthread_cond_signal( &pool->m_workingCondition );
                    pthread_mutex_unlock( &pool->m_taskMutex );
                    return NULL;
                }

                next_assert( pool->m_numTasks > 0 );

                task = pool->m_tasks[pool->m_numTasks-1];

                pool->m_numTasks--;
                pool->m_numWorking++;
            }
            pthread_mutex_unlock( &pool->m_taskMutex );

            task.func( task.arg );

            pthread_mutex_lock( &pool->m_taskMutex );
            {
                next_assert( pool->m_numWorking > 0 );

                pool->m_numWorking--;

                if ( !pool->m_stop && pool->m_numWorking == 0 && pool->m_numTasks == 0 )
                {
                    pool->m_finishTime = next_platform_time();
                    pthread_cond_signal( &pool->m_workingCondition );
                }
            }
            pthread_mutex_unlock( &pool->m_taskMutex );
        }

        return NULL;
    }

private:

    double m_startTime;
    double m_finishTime;

    int m_maxTasks;
    int m_numThreads;
    int m_numTasks;
    int m_numWorking;
    bool m_stop;

    pthread_mutex_t m_taskMutex;
    pthread_cond_t m_taskCondition;
    pthread_cond_t m_workingCondition;

    struct TaskData
    {
        platform_thread_func_t func;
        void * arg;
    };

    TaskData * m_tasks;
};

#else // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

typedef void (*platform_thread_func_t)( void *arg );

class ThreadPool
{
public:

    ThreadPool( int numThreads )
    {
        next_assert( numThreads >= 1 );

        m_startTime = 0.0;
        m_finishTime = 0.0;

        m_stop = false;
        m_maxTasks = numThreads;
        m_numThreads = numThreads;
        m_numTasks = 0;
        m_numWorking = 0;

        m_tasks = (TaskData*) malloc( sizeof(TaskData) * numThreads );
        nextw_assert( m_tasks );

        InitializeCriticalSectionAndSpinCount( (LPCRITICAL_SECTION)&m_taskMutex, 0xFF );
        
        InitializeConditionVariable( &m_taskCondition );
        InitializeConditionVariable( &m_workingCondition );

        for ( int i = 0; i < numThreads; i++) 
        {
            HANDLE thread = CreateThread( NULL, 0, WorkerThreadFunction, this, 0, NULL );
#if HIGH_PRIORITY_WORKER_THREADS
            SetThreadPriority( thread, THREAD_PRIORITY_TIME_CRITICAL );
#endif // #if HIGH_PRIORITY_WORKER_THREADS
        }
    }

    ~ThreadPool()
    {
        EnterCriticalSection( &m_taskMutex );
        
        m_stop = true;

        WakeConditionVariable( &m_taskCondition );

        LeaveCriticalSection( &m_taskMutex );

        Join();

        DeleteCriticalSection( &m_taskMutex );

        free( m_tasks );
        m_tasks = NULL;
    }

    void StartTimer()
    {
        EnterCriticalSection( &m_taskMutex );
        m_startTime = next_platform_time();
        LeaveCriticalSection( &m_taskMutex );
    }

    void AddTask( platform_thread_func_t func, void * arg )
    {
        EnterCriticalSection( &m_taskMutex );
        {
            next_assert( m_numTasks >= 0 );
            next_assert( m_numTasks < m_maxTasks );
            m_tasks[m_numTasks].func = func;
            m_tasks[m_numTasks].arg = arg;
            m_numTasks++;

            WakeConditionVariable( &m_taskCondition );
        }
        LeaveCriticalSection( &m_taskMutex );
    }

    void Join()
    {
        EnterCriticalSection( &m_taskMutex );
        while (1) 
        {
            if ( m_numTasks > 0 || ( !m_stop && m_numWorking > 0 ) || ( m_stop && m_numThreads != 0 ) ) 
            {
                SleepConditionVariableCS( &m_workingCondition, &m_taskMutex, 10 );
            } 
            else 
            {
                break;
            }
        }
        LeaveCriticalSection( &m_taskMutex );
    }

    double GetTotalTaskTime()
    {
        EnterCriticalSection( &m_taskMutex );
        double totalTaskTime = m_finishTime - m_startTime;
        LeaveCriticalSection( &m_taskMutex );
        return totalTaskTime;
    }

protected:

    static DWORD WINAPI WorkerThreadFunction( void * arg )
    {
        ThreadPool * pool = (ThreadPool*) arg;

        while ( true )
        {
            TaskData task;

            EnterCriticalSection( &pool->m_taskMutex );
            {
                while ( pool->m_numTasks == 0 && !pool->m_stop )
                {
                    SleepConditionVariableCS( &pool->m_taskCondition, &pool->m_taskMutex, 1000 );
                }

                if ( pool->m_stop )
                {
                    next_assert( pool->m_numThreads > 0 );
                    pool->m_numThreads--;
                    WakeConditionVariable( &pool->m_workingCondition );
                    LeaveCriticalSection( &pool->m_taskMutex );
                    return NULL;
                }

                next_assert( pool->m_numTasks > 0 );

                task = pool->m_tasks[pool->m_numTasks-1];

                pool->m_numTasks--;
                pool->m_numWorking++;
            }
            LeaveCriticalSection( &pool->m_taskMutex );

            task.func( task.arg );

            EnterCriticalSection( &pool->m_taskMutex );
            {
                next_assert( pool->m_numWorking > 0 );

                pool->m_numWorking--;

                if ( !pool->m_stop && pool->m_numWorking == 0 && pool->m_numTasks == 0 )
                {
                    pool->m_finishTime = next_platform_time();
                    WakeConditionVariable( &pool->m_workingCondition );
                }
            }
            LeaveCriticalSection( &pool->m_taskMutex );
        }

        return NULL;
    }

private:

    double m_startTime;
    double m_finishTime;

    int m_maxTasks;
    int m_numThreads;
    int m_numTasks;
    int m_numWorking;
    bool m_stop;

    CRITICAL_SECTION m_taskMutex;
    CONDITION_VARIABLE m_taskCondition;
    CONDITION_VARIABLE m_workingCondition;

    struct TaskData
    {
        platform_thread_func_t func;
        void * arg;
    };

    TaskData * m_tasks;
};

#endif // #if NEXT_PLATFORM == NEXT_PLATFORM_LINUX || NEXT_PLATFORM == NEXT_PLATFORM_MAC

// ---------------------------------------------------------------------------

struct send_packets_data_t
{
    next_server_t * server;
    int start_index;
    int finish_index;
};

void send_packets_thread( void * arg )
{
    send_packets_data_t * data = (send_packets_data_t*) arg;

    next_assert( data );

    next_server_t * server = data->server;

    const int start_index = data->start_index;
    const int finish_index = data->finish_index;

    next_address_t to;
    next_address_parse( &to, "192.164.1.3" );

    for ( int i = start_index; i < finish_index; i++ )
    {
        for ( int j = 0; j < 10; j++ )
        {
            uint64_t packet_id;
            to.port = 30000 + start_index + i;
            uint8_t * packet_data = next_server_start_packet( server, &to, &packet_id );
            if ( packet_data )
            {
                memset( packet_data, 0, NEXT_MTU );
                next_server_finish_packet( server, packet_id, packet_data, NEXT_MTU );
            }
        }
    }
}

#endif // #if LOAD_TEST

#ifdef __linux__

static void pin_thread_to_cpu( int cpu ) 
{
    int num_cpus = sysconf( _SC_NPROCESSORS_ONLN );
    next_assert( cpu >= 0 );
    next_assert( cpu < num_cpus );

    cpu_set_t cpuset;
    CPU_ZERO( &cpuset );
    CPU_SET( cpu, &cpuset );

    pthread_t current_thread = pthread_self();    

    pthread_setaffinity_np( current_thread, sizeof(cpu_set_t), &cpuset );
}

#endif // #ifdef __linux__

static inline int generate_packet( uint8_t * packet_data, int max_size )
{
    // todo
    max_size = 100;

    const int packet_bytes = 1 + rand() % ( max_size - 1 );
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        packet_data[i] = (uint8_t) ( start + i ) % 256;
    }
    return packet_bytes;
}

static inline bool verify_packet( uint8_t * packet_data, int packet_bytes )
{
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        if ( packet_data[i] != (uint8_t) ( ( start + i ) % 256 ) )
            return false;
    }
    return true;
}

int main()
{
    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    if ( !next_init() )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

    const char * bind_address = "0.0.0.0:40000";
    const char * public_address = "127.0.0.1:40000";
    
    next_server_socket_t * server_socket = next_server_socket_create( NULL, public_address );
    if ( !server_socket )
    {
        next_error( "could not create server socket" );
        return 1;
    }

    const int num_queues = next_server_socket_num_queues( server_socket );

#ifdef __linux__
    pin_thread_to_cpu( num_queues * 2 );
#endif // #ifdef __linux__

#if LOAD_TEST

    ThreadPool send_thread_pool( NUM_SEND_THREADS );

    send_packets_data_t send_data[NUM_SEND_THREADS];

    for ( int i = 0; i < NUM_SEND_THREADS; i++ )
    {
        send_data[i].server = server;
        send_data[i].start_index = i * (1000/NUM_SEND_THREADS);
        send_data[i].finish_index = (i+1) * (1000/NUM_SEND_THREADS);
        if ( send_data[i].finish_index >= 1000 )
        {
            send_data[i].finish_index = 999;
        }
    }

#endif // #if LOAD_TEST

    next_address_t client_address;
    double last_client_packet_time;

    while ( !quit )
    {
        next_server_socket_receive_packets( server_socket );

        next_server_socket_process_packets_t * packets = next_server_socket_process_packets( server_socket );

        for ( int i = 0; i < packets->num_packets; i++ )
        {
            char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_info( "server received %d byte packet from %s", packets->packet_bytes[i], next_address_to_string( &packets->from[i], buffer ) );
            client_address = packets->from[i];
            last_client_packet_time = next_platform_time();

            uint64_t packet_id;
            uint8_t * packet_data = next_server_socket_start_packet( server_socket, &client_address, &packet_id );
            if ( packet_data )
            {
                const int packet_bytes = generate_packet( packet_data, NEXT_MTU );
                next_server_socket_finish_packet( server_socket, packet_id, packet_data, packet_bytes );
            }
        }

        next_server_socket_update( server_socket );

#if LOAD_TEST

        for ( int i = 0; i < NUM_SEND_THREADS; i++ )
        {
            send_thread_pool.AddTask( send_packets_thread, send_data + i );
        }

#endif // #if LOAD_TEST

        next_platform_sleep( 1.0 / 100.0 );

        next_server_socket_send_packets( server_socket );
    }

    next_info( "stopping" );

    next_server_socket_stop( server_socket );

    while ( next_server_socket_state( server_socket ) != NEXT_SERVER_SOCKET_STOPPED )
    {
        next_server_socket_receive_packets( server_socket );
        next_server_socket_update( server_socket );
        next_platform_sleep( 1.0 / 100.0 );
    }

    next_info( "stopped" );

    next_server_socket_destroy( server_socket );

    next_term();

    return 0;
}
