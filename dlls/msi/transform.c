/*
 * Implementation of the Microsoft Installer (msi.dll)
 *
 * Copyright 2010 Mike Kaplinskiy
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

#include <stdarg.h>
#include <assert.h>

#define COBJMACROS
#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "msi.h"
#include "msiquery.h"
#include "objbase.h"
#include "objidl.h"
#include "winnls.h"
#include "msipriv.h"
#include "query.h"

#include "wine/debug.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(msidb);

static WCHAR szTables[]  = { '_','T','a','b','l','e','s',0 };
static WCHAR szColumns[] = { '_','C','o','l','u','m','n','s',0 };
static const WCHAR szStringData[] = {
    '_','S','t','r','i','n','g','D','a','t','a',0 };
static const WCHAR szStringPool[] = {
    '_','S','t','r','i','n','g','P','o','o','l',0 };

static inline UINT bytes_per_column( const UINT col_type, UINT bytes_per_strref )
{
    if( MSITYPE_IS_BINARY(col_type) )
        return 2;

    if( col_type & MSITYPE_STRING )
        return bytes_per_strref;

    if( (col_type & 0xff) <= 2)
        return 2;

    if( (col_type & 0xff) != 4 )
        ERR("Invalid column size!\n");

    return 4;
}

static inline UINT read_raw_int(const BYTE *data, UINT col, UINT bytes)
{
    UINT ret = 0, i;

    for (i = 0; i < bytes; i++)
        ret += (data[col + i] << i * 8);

    return ret;
}

static void dump_record( MSIRECORD *rec )
{
    UINT i, n;

    n = MSI_RecordGetFieldCount( rec );
    TRACE("(");
    for( i=1; i<=n; i++ )
    {
        LPCWSTR sval = MSI_RecordGetString( rec, i );

        if( MSI_RecordIsNull( rec, i ) )
            MESSAGE("[]");
        else if( (sval = MSI_RecordGetString( rec, i )) )
            MESSAGE("[%s]", debugstr_w(sval));
        else
            MESSAGE("[0x%08x]", MSI_RecordGetInteger( rec, i ) );
        if (i != n)
            MESSAGE(",");
    }
    MESSAGE(")\n");
}

static void dump_table( const string_table *st, const USHORT *rawdata, UINT rawsize )
{
    LPCWSTR sval;
    UINT i;

    for( i=0; i<(rawsize/2); i++ )
    {
        sval = msi_string_lookup_id( st, rawdata[i] );
        MESSAGE(" %04x %s\n", rawdata[i], debugstr_w(sval) );
    }
}

static void dump_table_data(MSIVIEW *view)
{
    UINT num_rows, i;
    LPWSTR table;

    if (view->ops->get_dimensions(view, &num_rows, NULL) != ERROR_SUCCESS)
        return;

    view->ops->get_column_info( view, 1, NULL, NULL, NULL, &table);

    MESSAGE("Dumping contents of table %s\n", debugstr_w(table));
    for (i = 0; i < num_rows; ++i)
    {
        MSIRECORD *rec;
        if (view->ops->get_row( view, i, &rec ) != ERROR_SUCCESS)
            return;
        dump_record(rec);
    }
}

/* FIXME: These 3 should probably not be copied */

/* XXX Is this supposed to be different than msi_stream_name? */
static UINT msi_record_encoded_stream_name( MSIVIEW *tv, MSIRECORD *rec, LPWSTR *pstname )
{
    LPWSTR stname = NULL, sval, p;
    UINT num_cols;
    DWORD len;
    UINT i, r;

    TRACE("%p %p\n", tv, rec);

    r = tv->ops->get_dimensions(tv, NULL, &num_cols);
    if (r != ERROR_SUCCESS)
        return r;

    r = tv->ops->get_column_info(tv, 1, NULL, NULL, NULL, &stname);
    if (r != ERROR_SUCCESS)
        goto err;
    len = lstrlenW( stname ) + 1;

    for ( i = 0; i < num_cols; i++ )
    {
        UINT coltype;
        r = tv->ops->get_column_info(tv, i+1, NULL, &coltype, NULL, NULL);
        if (r != ERROR_SUCCESS)
            goto err;

        if ( coltype & MSITYPE_KEY )
        {
            sval = msi_dup_record_field( rec, i + 1 );
            if ( !sval )
            {
                r = ERROR_OUTOFMEMORY;
                goto err;
            }

            len += lstrlenW( szDot ) + lstrlenW ( sval );
            p = msi_realloc ( stname, len*sizeof(WCHAR) );
            if ( !p )
            {
                r = ERROR_OUTOFMEMORY;
                goto err;
            }
            stname = p;

            lstrcatW( stname, szDot );
            lstrcatW( stname, sval );

            msi_free( sval );
        }
    }

    *pstname = encode_streamname( FALSE, stname );
    msi_free( stname );

    return ERROR_SUCCESS;

err:
    msi_free ( stname );
    *pstname = NULL;
    return r;
}

static UINT msi_read_transform_record( MSIVIEW *tv, const string_table *st, IStorage *stg,
                                       const BYTE *rawdata, UINT bytes_per_strref, MSIRECORD **record )
{
    UINT i, val, ofs = 0;
    USHORT mask;
    UINT num_cols;
    UINT col_type;
    UINT r;
    MSIRECORD *rec = NULL;

    mask = rawdata[0] | (rawdata[1] << 8);
    rawdata += 2;

    r = tv->ops->get_dimensions(tv, NULL, &num_cols);
    if (r != ERROR_SUCCESS)
        return r;

    rec = MSI_CreateRecord( num_cols );
    if( !rec )
    {
        r = ERROR_OUTOFMEMORY;
        goto err;
    }

    TRACE("row ->\n");
    for( i=0; i< num_cols; i++ )
    {
        if ( (mask&1) && (i>=(mask>>8)) )
            break;

        r = tv->ops->get_column_info(tv, i+1, NULL, &col_type, NULL, NULL);
        if (r != ERROR_SUCCESS)
            goto err;

        /* all keys must be present */
        if (!( mask&1 || col_type & MSITYPE_KEY || mask & (1<<i) ))
            continue;

        /* XXX Doesn't this read an incomplete record if we put it here?
            On the other hand, if we do another loop for streams, then
            there is at most one stream per record? */
        if( MSITYPE_IS_BINARY(col_type) )
        {
            LPWSTR encname;
            IStream *stm = NULL;
            ofs += bytes_per_column( col_type, bytes_per_strref );

            r = msi_record_encoded_stream_name( tv, rec, &encname );
            if ( r != ERROR_SUCCESS )
                goto err;

            r = IStorage_OpenStream( stg, encname, NULL,
                     STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &stm );
            msi_free( encname );
            if ( r != ERROR_SUCCESS )
                goto err;

            MSI_RecordSetStream( rec, i+1, stm );
            TRACE(" field %d [%s]\n", i+1, debugstr_w(encname));
        }
        else if( col_type & MSITYPE_STRING )
        {
            LPCWSTR sval;

            val = read_raw_int(rawdata, ofs, bytes_per_strref);
            sval = msi_string_lookup_id( st, val );
            MSI_RecordSetStringW( rec, i+1, sval );
            TRACE(" field %d [%s]\n", i+1, debugstr_w(sval));
            ofs += bytes_per_strref;
        }
        else
        {
            UINT n = bytes_per_column( col_type, bytes_per_strref );
            switch( n )
            {
            case 2:
                val = read_raw_int(rawdata, ofs, n);
                if (val)
                    MSI_RecordSetInteger( rec, i+1, val-0x8000 );
                TRACE(" field %d [0x%04x]\n", i+1, val );
                break;
            case 4:
                val = read_raw_int(rawdata, ofs, n);
                if (val)
                    MSI_RecordSetInteger( rec, i+1, val^0x80000000 );
                TRACE(" field %d [0x%08x]\n", i+1, val );
                break;
            default:
                ERR("oops - unknown column width %d\n", n);
                break;
            }
            ofs += n;
        }
    }

    *record = rec;
    rec = NULL;
    return ERROR_SUCCESS;

err:
    msiobj_release( &rec->hdr );
    *record = NULL;
    if (r == ERROR_SUCCESS) FIXME("Should not be here!\n");
    return r;
}

UINT msi_get_transform_record( MSITRANSFORMDATA *transform, MSITRANSFORMRECORD *data, MSIVIEW *view, MSIRECORD **record )
{
    UINT rawsize = 0;
    BYTE *rawdata = NULL;
    UINT r;

    read_stream_data( transform->storage, data->table, TRUE, &rawdata, &rawsize );
    if ( !rawdata )
    {
        TRACE("table %s empty\n", debugstr_w(data->table) );
        return ERROR_INVALID_TABLE;
    }

    r = msi_read_transform_record(view, transform->strings, transform->storage,
                                  &rawdata[data->data_offset], transform->bytes_per_strref,
                                  record );

    msi_free( rawdata );

    return r;
}

UINT msi_apply_transform_record( MSITRANSFORMDATA *transform, MSIVIEW *view, UINT mask, MSIRECORD *record )
{
    UINT r;
    UINT num_cols, row;

    r = view->ops->get_dimensions(view, NULL, &num_cols);
    if( r != ERROR_SUCCESS )
        return r;

    if (TRACE_ON(msidb)) dump_record( record );

    r = msi_view_find_row( transform->db, view, record, &row );
    if (r == ERROR_SUCCESS)
    {
        if (!mask)
        {
            TRACE("deleting row [%d]:\n", row);
            r = view->ops->delete_row( view, row );
            if (r != ERROR_SUCCESS)
                WARN("failed to delete row %u\n", r);
        }
        else if (mask & 1)
        {
            TRACE("modifying full row [%d]:\n", row);
            r = view->ops->set_row( view, row, record, (1 << num_cols) - 1 );
            if (r != ERROR_SUCCESS)
                WARN("failed to modify row %u\n", r);
        }
        else
        {
            TRACE("modifying masked row [%d]:\n", row);
            r = view->ops->set_row( view, row, record, mask );
            if (r != ERROR_SUCCESS)
                WARN("failed to modify row %u\n", r);
        }
    }
    else
    {
        TRACE("inserting row\n");
        r = view->ops->insert_row( view, record, -1, FALSE );
        if (r != ERROR_SUCCESS)
            WARN("failed to insert row %u\n", r);
    }

    return ERROR_SUCCESS;
}

static UINT msi_apply_transform_internal_record( MSITRANSFORMDATA *transform, MSIVIEW *view, UINT mask, MSIRECORD *record,
                                                 LPWSTR coltable, UINT *colcol )
{
    LPWSTR table;
    UINT r;
    WCHAR column_table[32];
    DWORD sz = 32;
    UINT number = MSI_NULL_INTEGER;

    TRACE("%p %p %x %p\n", transform, view, mask, record);

    r = view->ops->get_column_info( view, 1, NULL, NULL, NULL, &table );
    if (r != ERROR_SUCCESS)
        return r;

    if (!lstrcmpW(table, szColumns))
    {
        MSI_RecordGetStringW( record, 1, column_table, &sz );
        number = MSI_RecordGetInteger( record, 2 );

        /*
         * Native msi seems writes nul into the Number (2nd) column of
         * the _Columns table, only when the columns are from a new table
         */
        if ( number == MSI_NULL_INTEGER )
        {
            /* reset the column number on a new table */
            if ( lstrcmpW(coltable, column_table) )
            {
                *colcol = 0;
                lstrcpyW( coltable, column_table );
            }

            /* fix nul column numbers */
            MSI_RecordSetInteger( record, 2, ++*colcol );
        }
        else
        {
            MSIVIEW *cache_view;
            /* Cache the table, so we update columns correctly */
            if (TABLE_CreateView(transform->db, column_table, &cache_view) == ERROR_SUCCESS)
                cache_view->ops->delete( cache_view );
        }
    }
    msi_free( table );

    r = msi_apply_transform_record(transform, view, mask, record);

    return r;
}

static UINT msi_parse_table_transform( MSITRANSFORMDATA *transform, LPWSTR name )
{
    UINT rawsize = 0;
    BYTE *rawdata = NULL;
    MSIVIEW *tv = NULL;
    UINT r, n, sz, i, mask;
    UINT num_cols;
    UINT *column_types = NULL;
    MSITRANSFORMRECORD *record;

    TRACE("%p %s\n", transform, debugstr_w(name) );

    /* read the transform data */
    read_stream_data( transform->storage, name, TRUE, &rawdata, &rawsize );
    if ( !rawdata )
    {
        TRACE("table %s empty\n", debugstr_w(name) );
        return ERROR_INVALID_TABLE;
    }

    /* create a table view */
    r = TABLE_CreateView( transform->db, name, &tv );
    if( r != ERROR_SUCCESS )
    {
        r = ERROR_SUCCESS;
        goto err;
    }

    r = tv->ops->execute( tv, NULL );
    if( r != ERROR_SUCCESS )
        goto err;

    r = tv->ops->get_dimensions(tv, NULL, &num_cols);
    if( r != ERROR_SUCCESS )
        goto err;

    TRACE("name = %s columns = %u raw size = %u\n",
          debugstr_w(name), num_cols, rawsize );

    column_types = msi_alloc( num_cols * sizeof(UINT) );
    if (!column_types)
        goto err;

    for( i=0; i< num_cols; i++ )
    {
        r = tv->ops->get_column_info(tv, i+1, NULL, &column_types[i], NULL, NULL);
        if (r != ERROR_SUCCESS)
            goto err;
    }

    /* interpret the data */
    r = ERROR_SUCCESS;
    for( n=0; n < rawsize;  )
    {
        mask = rawdata[n] | (rawdata[n+1] << 8);

        /*
         * if the low bit is set, columns are continuous and
         * the number of columns is specified in the high byte
         */
        /*
         * If the low bit is not set, mask is a bitmask.
         * Excepting for key fields, which are always present,
         *  each bit indicates that a field is present in the transform record.
         *
         * mask == 0 is a special case ... only the keys will be present
         * and it means that this row should be deleted.
         */
        sz = 2;
        for( i=0; i< num_cols; i++ )
        {
            if( mask & 1 || column_types[i] & MSITYPE_KEY || mask&(1<<i) )
                sz += bytes_per_column( column_types[i], transform->bytes_per_strref );
        }

        /* check we didn't run of the end of the table */
        if ( (n+sz) > rawsize )
        {
            ERR("borked.\n");
            dump_table( transform->strings, (USHORT *)rawdata, rawsize );
            r = ERROR_FUNCTION_FAILED;
            break;
        }

        record = msi_alloc( sizeof(*record) );
        if (!record)
        {
            r = ERROR_OUTOFMEMORY;
            goto err;
        }

        record->table = strdupW(name);
        record->mask = mask;
        record->data_offset = n;
        list_add_tail(&transform->records, &record->entry);

        n += sz;
    }

err:
    /* no need to free the table, it's associated with the database */
    msi_free( rawdata );
    msi_free( column_types );
    if( tv )
        tv->ops->delete( tv );

    return r;
}

UINT msi_begin_transform( MSIDATABASE *db, IStorage *stg, BOOL structure, MSITRANSFORMDATA **transform )
{
    IEnumSTATSTG *stgenum = NULL;
    HRESULT ret;
    STATSTG stat;
    UINT r = ERROR_SUCCESS;
    MSITRANSFORMDATA *t;
    MSITRANSFORMRECORD *trec, *trec2;
    MSIRECORD *record;
    MSIVIEW *view;
    WCHAR name[0x40];
    UINT count;

    WCHAR coltable[0x40] = {0};
    UINT colcol = 0;

    TRACE("%p %p %p\n", db, stg, transform);

    t = msi_alloc( sizeof(*t) );
    if (!t)
        return ERROR_OUTOFMEMORY;

    t->db = db;
    t->storage = stg;
    IStorage_AddRef( stg );
    list_init( &t->records );
    t->strings = msi_load_string_table( stg, &t->bytes_per_strref );
    if( !t->strings )
        goto end;

    /* Get the structure transforms first */
    r = msi_parse_table_transform(t, szTables);
    if (r != ERROR_SUCCESS && r != ERROR_INVALID_TABLE)
        goto end;

    r = msi_parse_table_transform(t, szColumns);
    if (r != ERROR_SUCCESS && r != ERROR_INVALID_TABLE)
        goto end;


    LIST_FOR_EACH_ENTRY_SAFE(trec, trec2, &t->records, MSITRANSFORMRECORD, entry)
    {
        r = TABLE_CreateView(db, trec->table, &view);
        if (r != ERROR_SUCCESS)
            goto end;

        r = msi_get_transform_record(t, trec, view, &record);
        if (r != ERROR_SUCCESS)
        {
            view->ops->delete( view );
            goto end;
        }

        r = msi_apply_transform_internal_record(t, view, trec->mask, record, coltable, &colcol);
        msiobj_release( &record->hdr );
        view->ops->delete( view );
        if (r != ERROR_SUCCESS)
            goto end;

        if (!structure)
        {
            list_remove(&trec->entry);
            msi_free( trec->table );
            msi_free( trec );
        }
    }

    ret = IStorage_EnumElements( stg, 0, NULL, 0, &stgenum );
    if( FAILED( ret ) )
    {
        r = ERROR_FUNCTION_FAILED;
        goto end;
    }

    while ( TRUE )
    {
        ret = IEnumSTATSTG_Next( stgenum, 1, &stat, &count );
        if ( FAILED( ret ) || !count )
            break;

        decode_streamname( stat.pwcsName, name );
        CoTaskMemFree( stat.pwcsName );
        if ( name[0] != 0x4840 )
            continue;

        if ( !lstrcmpW( name+1, szStringPool ) ||
             !lstrcmpW( name+1, szStringData ) ||
             !lstrcmpW( name+1, szTables ) ||
             !lstrcmpW( name+1, szColumns ) )
            continue;

        r = msi_parse_table_transform( t, name+1 );
        if (r != ERROR_SUCCESS)
        {
            FIXME("Table %s failed to parse\n", debugstr_w(name+1));
            goto end;
        }
    }

    *transform = t;
    t = NULL;

end:
    if ( stgenum )
        IEnumSTATSTG_Release( stgenum );
    if (t)
        msi_destroy_transform( t );

    return r;
}

void msi_destroy_transform( MSITRANSFORMDATA *transform )
{
    MSITRANSFORMRECORD *rec, *rec2;

    LIST_FOR_EACH_ENTRY_SAFE(rec, rec2, &transform->records, MSITRANSFORMRECORD, entry)
    {
        msi_free( rec->table );
        msi_free( rec );
    }

    IStorage_Release( transform->storage );
    msi_destroy_stringtable( transform->strings );
    msi_free( transform );
}

UINT msi_apply_transform(MSIDATABASE *db, IStorage *stg)
{
    UINT r = ERROR_SUCCESS;
    MSITRANSFORMDATA *transform;
    MSITRANSFORMRECORD *trec;
    MSIRECORD *record;
    MSIVIEW *view;

    TRACE("Applying transform\n");

    r = msi_begin_transform(db, stg, FALSE, &transform);
    if (r != ERROR_SUCCESS)
    {
        FIXME("Failed structure\n");
        return r;
    }

    LIST_FOR_EACH_ENTRY(trec, &transform->records, MSITRANSFORMRECORD, entry)
    {
        r = TABLE_CreateView(db, trec->table, &view);
        if (r != ERROR_SUCCESS)
            goto end;

        r = msi_get_transform_record(transform, trec, view, &record);
        if (r != ERROR_SUCCESS)
        {
            view->ops->delete( view );
            goto end;
        }

        r = msi_apply_transform_record(transform, view, trec->mask, record);
        msiobj_release( &record->hdr );
        if (r != ERROR_SUCCESS)
        {
            view->ops->delete( view );
            goto end;
        }

        view->ops->delete( view );
    }

    append_storage_to_db( db, stg );

end:
    msi_destroy_transform( transform );
    return r;
}
