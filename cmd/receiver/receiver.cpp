/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"

int main()
{
    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    if ( !next_init() )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

    while ( !quit )
    {
        // ...

        next_platform_sleep( 1.0 / 100.0 );
    }

    next_term();

    return 0;
}
