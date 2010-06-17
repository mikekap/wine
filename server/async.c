/*
 * Server-side async I/O support
 *
 * Copyright (C) 2007 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "object.h"
#include "file.h"
#include "request.h"

struct async_poll_fd
{
    struct list          queue_entry;     /* entry in async queue list */
    struct list          async_entry;     /* entry in async list */
    struct async_queue  *queue;           /* queue containing this async */
    struct async        *async;
    int                  pollev;          /* poll events this async waiting for */
    int                  woken;
};

struct async
{
    struct object        obj;             /* object header */
    struct thread       *thread;          /* owning thread */
    unsigned int         status;          /* current status */
    struct timeout_user *timeout;
    unsigned int         timeout_status;  /* status to report upon timeout */
    struct event        *event;
    struct completion   *completion;
    apc_param_t          comp_key;
    async_data_t         data;            /* data for async I/O call */
    struct list          pollfds;
};

static void async_dump( struct object *obj, int verbose );
static void async_destroy( struct object *obj );

static const struct object_ops async_ops =
{
    sizeof(struct async),      /* size */
    async_dump,                /* dump */
    no_get_type,               /* get_type */
    no_add_queue,              /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* satisfied */
    no_signal,                 /* signal */
    no_get_fd,                 /* get_fd */
    no_map_access,             /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_lookup_name,            /* lookup_name */
    no_open_file,              /* open_file */
    no_close_handle,           /* close_handle */
    async_destroy              /* destroy */
};


struct async_queue
{
    struct object        obj;             /* object header */
    struct fd           *fd;              /* file descriptor owning this queue */
    struct list          queue;           /* queue of async objects */
};

static void async_queue_dump( struct object *obj, int verbose );

static const struct object_ops async_queue_ops =
{
    sizeof(struct async_queue),      /* size */
    async_queue_dump,                /* dump */
    no_get_type,                     /* get_type */
    no_add_queue,                    /* add_queue */
    NULL,                            /* remove_queue */
    NULL,                            /* signaled */
    NULL,                            /* satisfied */
    no_signal,                       /* signal */
    no_get_fd,                       /* get_fd */
    no_map_access,                   /* map_access */
    default_get_sd,                  /* get_sd */
    default_set_sd,                  /* set_sd */
    no_lookup_name,                  /* lookup_name */
    no_open_file,                    /* open_file */
    no_close_handle,                 /* close_handle */
    no_destroy                       /* destroy */
};


static inline void async_progress( struct async *async )
{
    struct async_poll_fd *curr;

    LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
    {
        if (curr->queue->fd) fd_async_progress( curr->queue->fd, &async->data, curr->pollev, async->status );
    }
}

static void async_dump( struct object *obj, int verbose )
{
    struct async *async = (struct async *)obj;
    assert( obj->ops == &async_ops );
    fprintf( stderr, "Async thread=%p\n", async->thread );
}

static void async_destroy( struct object *obj )
{
    struct async *async = (struct async *)obj;
    struct async_poll_fd *curr, *next;
    assert( obj->ops == &async_ops );

    LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
    {
        list_remove( &curr->queue_entry );
    }
    async->status = -1;
    async_progress( async );

    LIST_FOR_EACH_ENTRY_SAFE( curr, next, &async->pollfds, struct async_poll_fd, async_entry )
    {
        release_object( curr->queue );
        free( curr );
    }
    if (async->timeout) remove_timeout_user( async->timeout );
    if (async->event) release_object( async->event );
    if (async->completion) release_object( async->completion );
    release_object( async->thread );
}

static void async_queue_dump( struct object *obj, int verbose )
{
    struct async_queue *async_queue = (struct async_queue *)obj;
    assert( obj->ops == &async_queue_ops );
    fprintf( stderr, "Async queue fd=%p\n", async_queue->fd );
}

/* notifies client thread of new status of its async request */
void async_terminate( struct async_queue *queue, struct async *async, unsigned int status )
{
    apc_call_t data;
    struct async_poll_fd *curr;
    int allwoken;

    assert( status != STATUS_PENDING );

    if (async->status != STATUS_PENDING)
    {
        /* already terminated, just update status */
        async->status = status;
        return;
    }

    if (status == STATUS_ALERTED)
    {
        assert( queue );

        allwoken = 1;
        LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
        {
            if (curr->queue == queue)
                curr->woken = 1;
            if (!curr->woken && curr->pollev & ~POLLERR)
                allwoken = 0;
        }

        if (!allwoken) return;
    }

    memset( &data, 0, sizeof(data) );
    data.type            = APC_ASYNC_IO;
    data.async_io.func   = async->data.callback;
    data.async_io.user   = async->data.arg;
    data.async_io.sb     = async->data.iosb;
    data.async_io.status = status;
    thread_queue_apc( async->thread, &async->obj, &data );
    async->status = status;
    async_progress( async );

    grab_object( async );
    LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
    {
        release_object( async );  /* so that it gets destroyed when the async is done */
    }
    release_object( async );
}

/* callback for timeout on an async request */
static void async_timeout( void *private )
{
    struct async *async = private;

    async->timeout = NULL;
    async_terminate( NULL, async, async->timeout_status );
}

/* create a new async queue for a given fd */
struct async_queue *create_async_queue( struct fd *fd )
{
    struct async_queue *queue = alloc_object( &async_queue_ops );

    if (queue)
    {
        queue->fd = fd;
        list_init( &queue->queue );
    }
    return queue;
}

/* free an async queue, cancelling all async operations */
void free_async_queue( struct async_queue *queue )
{
    if (!queue) return;
    queue->fd = NULL;
    async_wake_up( queue, 0, STATUS_HANDLES_CLOSED );
    release_object( queue );
}

/* create an async */
struct async *create_async( struct thread *thread, const async_data_t *data )
{
    struct event *event = NULL;
    struct async *async;

    if (data->event && !(event = get_event_obj( thread->process, data->event, EVENT_MODIFY_STATE )))
        return NULL;

    if (!(async = alloc_object( &async_ops )))
    {
        if (event) release_object( event );
        return NULL;
    }

    async->thread  = (struct thread *)grab_object( thread );
    async->event   = event;
    async->status  = STATUS_PENDING;
    async->data    = *data;
    async->timeout = NULL;
    async->completion = NULL;
    list_init( &async->pollfds );

    if (event) reset_event( event );
    return async;
}

/* queue an async onto a fd's queue */
void queue_async( struct async_queue *queue, struct async *async, int pollev )
{
    struct async_poll_fd *pollfd;

    if (queue->fd)
    {
        if (!async->completion && list_empty( &async->pollfds ))
            async->completion = fd_get_completion( queue->fd, &async->comp_key );
        set_fd_signaled( queue->fd, 0 );
    }

    pollfd = malloc( sizeof(*pollfd) );
    pollfd->queue = (struct async_queue *) grab_object( queue );
    pollfd->async = (struct async *) grab_object( async );
    list_add_tail( &queue->queue, &pollfd->queue_entry );
    list_add_tail( &async->pollfds, &pollfd->async_entry );
    pollfd->pollev = pollev;
    pollfd->woken = 0;
}

/* set the timeout of an async operation */
void async_set_timeout( struct async *async, timeout_t timeout, unsigned int status )
{
    if (async->timeout) remove_timeout_user( async->timeout );
    if (timeout != TIMEOUT_INFINITE) async->timeout = add_timeout_user( timeout, async_timeout, async );
    else async->timeout = NULL;
    async->timeout_status = status;
}

/* store the result of the client-side async callback */
void async_set_result( struct object *obj, unsigned int status, unsigned int total, client_ptr_t apc )
{
    struct async *async = (struct async *)obj;
    struct async_poll_fd *curr;

    if (obj->ops != &async_ops) return;  /* in case the client messed up the APC results */

    assert( async->status != STATUS_PENDING );  /* it must have been woken up if we get a result */

    if (status == STATUS_PENDING)  /* restart it */
    {
        status = async->status;
        async->status = STATUS_PENDING;
        LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
            grab_object( async );

        if (status != STATUS_ALERTED)  /* it was terminated in the meantime */
            async_terminate( NULL, async, status );
        else
            async_progress( async );
    }
    else
    {
        if (async->timeout) remove_timeout_user( async->timeout );
        async->timeout = NULL;
        async->status = status;
        if (async->completion && async->data.cvalue)
            add_completion( async->completion, async->comp_key, async->data.cvalue, status, total );
        if (apc)
        {
            apc_call_t data;
            memset( &data, 0, sizeof(data) );
            data.type         = APC_USER;
            data.user.func    = apc;
            data.user.args[0] = async->data.arg;
            data.user.args[1] = async->data.iosb;
            data.user.args[2] = 0;
            thread_queue_apc( async->thread, NULL, &data );
        }
        if (async->event)
            set_event( async->event );
        else
        {
            LIST_FOR_EACH_ENTRY( curr, &async->pollfds, struct async_poll_fd, async_entry )
            {
                if (curr->queue->fd) set_fd_signaled( curr->queue->fd, 1 );
            }
        }
    }
}

int async_get_poll_events( struct async_queue *queue )
{
    struct list *ptr, *next;
    int ev = 0;
    int blocked = 0;

    if (!queue) return 0;

    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async_poll_fd *async = LIST_ENTRY( ptr, struct async_poll_fd, queue_entry );
        if (!async->woken)
            ev |= async->pollev;
        else
            blocked |= async->pollev;
    }
    return ev & ~blocked;
}

/* check if there are any queued async operations */
int async_queued( struct async_queue *queue, int pollev )
{
    struct list *ptr, *next;

    if (!queue) return 0;
    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async_poll_fd *async = LIST_ENTRY( ptr, struct async_poll_fd, queue_entry );

        if ( async->pollev == pollev || async->pollev & pollev || pollev == -1 )
            return 1;
    }
    return 0;
}

/* check if an async operation is waiting to be alerted */
int async_waiting( struct async_queue *queue, int pollev )
{
    struct list *ptr, *next;

    if (!queue) return 0;
    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async_poll_fd *async = LIST_ENTRY( ptr, struct async_poll_fd, queue_entry );

        if ( async->pollev == pollev || async->pollev & pollev || pollev == -1 )
            return !async->woken;
    }
    return 0;
}

int async_wake_up_by( struct async_queue *queue, struct process *process,
                      struct thread *thread, client_ptr_t iosb, unsigned int status )
{
    struct list *ptr, *next;
    int woken = 0;

    if (!queue || (!process && !thread && !iosb)) return 0;

    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async_poll_fd *async = LIST_ENTRY( ptr, struct async_poll_fd, queue_entry );
        if ( (!process || async->async->thread->process == process) &&
             (!thread || async->async->thread == thread) &&
             (!iosb || async->async->data.iosb == iosb) )
        {
            async_terminate( queue, async->async, status );
            woken++;
        }
    }
    return woken;
}

/* wake up async operations on the queue */
void async_wake_up( struct async_queue *queue, int events, unsigned int status )
{
    struct list *ptr, *next;

    if (!queue) return;

    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async_poll_fd *async = LIST_ENTRY( ptr, struct async_poll_fd, queue_entry );
        if (status == STATUS_ALERTED)
        {
            /* events == 0 is valid, and we only wake async->events == 0 */
            if ( events == async->pollev || events & async->pollev )
            {
                events &= ~async->pollev;
                async_terminate( queue, async->async, status );
            }

            if (!events)
                break;  /* only wake up the first one, for each event type */
        }
        else
            async_terminate( queue, async->async, status );
    }
}
