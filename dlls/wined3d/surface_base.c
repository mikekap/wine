/*
 * IWineD3DSurface Implementation of management(non-rendering) functions
 *
 * Copyright 1998 Lionel Ulmer
 * Copyright 2000-2001 TransGaming Technologies Inc.
 * Copyright 2002-2005 Jason Edmeades
 * Copyright 2002-2003 Raphael Junqueira
 * Copyright 2004 Christian Costa
 * Copyright 2005 Oliver Stieber
 * Copyright 2006-2008 Stefan Dösinger for CodeWeavers
 * Copyright 2007 Henri Verbeet
 * Copyright 2006-2007 Roderick Colenbrander
 * Copyright 2009-2010 Henri Verbeet for CodeWeavers
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
#include "wine/port.h"
#include "wined3d_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d_surface);

/* See also float_16_to_32() in wined3d_private.h */
static inline unsigned short float_32_to_16(const float *in)
{
    int exp = 0;
    float tmp = fabs(*in);
    unsigned int mantissa;
    unsigned short ret;

    /* Deal with special numbers */
    if (*in == 0.0f) return 0x0000;
    if(isnan(*in)) return 0x7C01;
    if (isinf(*in)) return (*in < 0.0f ? 0xFC00 : 0x7c00);

    if(tmp < powf(2, 10)) {
        do
        {
            tmp = tmp * 2.0f;
            exp--;
        }while(tmp < powf(2, 10));
    } else if(tmp >= powf(2, 11)) {
        do
        {
            tmp /= 2.0f;
            exp++;
        }while(tmp >= powf(2, 11));
    }

    mantissa = (unsigned int) tmp;
    if(tmp - mantissa >= 0.5f) mantissa++; /* round to nearest, away from zero */

    exp += 10;  /* Normalize the mantissa */
    exp += 15;  /* Exponent is encoded with excess 15 */

    if(exp > 30) { /* too big */
        ret = 0x7c00; /* INF */
    } else if(exp <= 0) {
        /* exp == 0: Non-normalized mantissa. Returns 0x0000 (=0.0) for too small numbers */
        while(exp <= 0) {
            mantissa = mantissa >> 1;
            exp++;
        }
        ret = mantissa & 0x3ff;
    } else {
        ret = (exp << 10) | (mantissa & 0x3ff);
    }

    ret |= ((*in < 0.0f ? 1 : 0) << 15); /* Add the sign */
    return ret;
}

/* *******************************************
   IWineD3DSurface IUnknown parts follow
   ******************************************* */
HRESULT WINAPI IWineD3DBaseSurfaceImpl_QueryInterface(IWineD3DSurface *iface, REFIID riid, LPVOID *ppobj)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    /* Warn ,but be nice about things */
    TRACE("(%p)->(%s,%p)\n", This,debugstr_guid(riid),ppobj);

    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IWineD3DBase)
        || IsEqualGUID(riid, &IID_IWineD3DResource)
        || IsEqualGUID(riid, &IID_IWineD3DSurface)) {
        IUnknown_AddRef((IUnknown*)iface);
        *ppobj = This;
        return S_OK;
        }
        *ppobj = NULL;
        return E_NOINTERFACE;
}

ULONG WINAPI IWineD3DBaseSurfaceImpl_AddRef(IWineD3DSurface *iface) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    ULONG ref = InterlockedIncrement(&This->resource.ref);
    TRACE("(%p) : AddRef increasing from %d\n", This,ref - 1);
    return ref;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetPrivateData(IWineD3DSurface *iface,
        REFGUID riid, const void *data, DWORD data_size, DWORD flags)
{
    return resource_set_private_data((IWineD3DResourceImpl *)iface, riid, data, data_size, flags);
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetPrivateData(IWineD3DSurface *iface,
        REFGUID guid, void *data, DWORD *data_size)
{
    return resource_get_private_data((IWineD3DResourceImpl *)iface, guid, data, data_size);
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_FreePrivateData(IWineD3DSurface *iface, REFGUID refguid)
{
    return resource_free_private_data((IWineD3DResourceImpl *)iface, refguid);
}

DWORD WINAPI IWineD3DBaseSurfaceImpl_SetPriority(IWineD3DSurface *iface, DWORD priority)
{
    return resource_set_priority((IWineD3DResourceImpl *)iface, priority);
}

DWORD WINAPI IWineD3DBaseSurfaceImpl_GetPriority(IWineD3DSurface *iface)
{
    return resource_get_priority((IWineD3DResourceImpl *)iface);
}

WINED3DRESOURCETYPE WINAPI IWineD3DBaseSurfaceImpl_GetType(IWineD3DSurface *iface)
{
    return resource_get_type((IWineD3DResourceImpl *)iface);
}

void * WINAPI IWineD3DBaseSurfaceImpl_GetParent(IWineD3DSurface *iface)
{
    TRACE("iface %p.\n", iface);

    return ((IWineD3DSurfaceImpl *)iface)->resource.parent;
}

void WINAPI IWineD3DBaseSurfaceImpl_GetDesc(IWineD3DSurface *iface, WINED3DSURFACE_DESC *desc)
{
    IWineD3DSurfaceImpl *surface = (IWineD3DSurfaceImpl *)iface;

    TRACE("iface %p, desc %p.\n", iface, desc);

    desc->format = surface->resource.format->id;
    desc->resource_type = surface->resource.resourceType;
    desc->usage = surface->resource.usage;
    desc->pool = surface->resource.pool;
    desc->size = surface->resource.size; /* dx8 only */
    desc->multisample_type = surface->currentDesc.MultiSampleType;
    desc->multisample_quality = surface->currentDesc.MultiSampleQuality;
    desc->width = surface->currentDesc.Width;
    desc->height = surface->currentDesc.Height;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetBltStatus(IWineD3DSurface *iface, DWORD flags)
{
    TRACE("iface %p, flags %#x.\n", iface, flags);

    switch (flags)
    {
        case WINEDDGBS_CANBLT:
        case WINEDDGBS_ISBLTDONE:
            return WINED3D_OK;

        default:
            return WINED3DERR_INVALIDCALL;
    }
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetFlipStatus(IWineD3DSurface *iface, DWORD flags)
{
    /* XXX: DDERR_INVALIDSURFACETYPE */

    TRACE("iface %p, flags %#x.\n", iface, flags);

    switch (flags)
    {
        case WINEDDGFS_CANFLIP:
        case WINEDDGFS_ISFLIPDONE:
            return WINED3D_OK;

        default:
            return WINED3DERR_INVALIDCALL;
    }
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_IsLost(IWineD3DSurface *iface) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    TRACE("(%p)\n", This);

    /* D3D8 and 9 loose full devices, ddraw only surfaces */
    return This->flags & SFLAG_LOST ? WINED3DERR_DEVICELOST : WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_Restore(IWineD3DSurface *iface) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    TRACE("(%p)\n", This);

    /* So far we don't lose anything :) */
    This->flags &= ~SFLAG_LOST;
    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetPalette(IWineD3DSurface *iface, IWineD3DPalette *Pal) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    IWineD3DPaletteImpl *PalImpl = (IWineD3DPaletteImpl *) Pal;
    TRACE("(%p)->(%p)\n", This, Pal);

    if(This->palette == PalImpl) {
        TRACE("Nop palette change\n");
        return WINED3D_OK;
    }

    if (This->palette)
        if (This->resource.usage & WINED3DUSAGE_RENDERTARGET)
            This->palette->flags &= ~WINEDDPCAPS_PRIMARYSURFACE;

    This->palette = PalImpl;

    if (PalImpl)
    {
        if (This->resource.usage & WINED3DUSAGE_RENDERTARGET)
            PalImpl->flags |= WINEDDPCAPS_PRIMARYSURFACE;

        return IWineD3DSurface_RealizePalette(iface);
    }
    else return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetColorKey(IWineD3DSurface *iface, DWORD flags, const WINEDDCOLORKEY *CKey)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;

    TRACE("iface %p, flags %#x, color_key %p.\n", iface, flags, CKey);

    if (flags & WINEDDCKEY_COLORSPACE)
    {
        FIXME(" colorkey value not supported (%08x) !\n", flags);
        return WINED3DERR_INVALIDCALL;
    }

    /* Dirtify the surface, but only if a key was changed */
    if (CKey)
    {
        switch (flags & ~WINEDDCKEY_COLORSPACE)
        {
            case WINEDDCKEY_DESTBLT:
                This->DestBltCKey = *CKey;
                This->CKeyFlags |= WINEDDSD_CKDESTBLT;
                break;

            case WINEDDCKEY_DESTOVERLAY:
                This->DestOverlayCKey = *CKey;
                This->CKeyFlags |= WINEDDSD_CKDESTOVERLAY;
                break;

            case WINEDDCKEY_SRCOVERLAY:
                This->SrcOverlayCKey = *CKey;
                This->CKeyFlags |= WINEDDSD_CKSRCOVERLAY;
                break;

            case WINEDDCKEY_SRCBLT:
                This->SrcBltCKey = *CKey;
                This->CKeyFlags |= WINEDDSD_CKSRCBLT;
                break;
        }
    }
    else
    {
        switch (flags & ~WINEDDCKEY_COLORSPACE)
        {
            case WINEDDCKEY_DESTBLT:
                This->CKeyFlags &= ~WINEDDSD_CKDESTBLT;
                break;

            case WINEDDCKEY_DESTOVERLAY:
                This->CKeyFlags &= ~WINEDDSD_CKDESTOVERLAY;
                break;

            case WINEDDCKEY_SRCOVERLAY:
                This->CKeyFlags &= ~WINEDDSD_CKSRCOVERLAY;
                break;

            case WINEDDCKEY_SRCBLT:
                This->CKeyFlags &= ~WINEDDSD_CKSRCBLT;
                break;
        }
    }

    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetPalette(IWineD3DSurface *iface, IWineD3DPalette **Pal) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    TRACE("(%p)->(%p)\n", This, Pal);

    *Pal = (IWineD3DPalette *) This->palette;
    return WINED3D_OK;
}

DWORD WINAPI IWineD3DBaseSurfaceImpl_GetPitch(IWineD3DSurface *iface)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    const struct wined3d_format *format = This->resource.format;
    DWORD ret;
    TRACE("(%p)\n", This);

    if ((format->flags & (WINED3DFMT_FLAG_COMPRESSED | WINED3DFMT_FLAG_BROKEN_PITCH)) == WINED3DFMT_FLAG_COMPRESSED)
    {
        /* Since compressed formats are block based, pitch means the amount of
         * bytes to the next row of block rather than the next row of pixels. */
        UINT row_block_count = (This->currentDesc.Width + format->block_width - 1) / format->block_width;
        ret = row_block_count * format->block_byte_count;
    }
    else
    {
        unsigned char alignment = This->resource.device->surface_alignment;
        ret = This->resource.format->byte_count * This->currentDesc.Width;  /* Bytes / row */
        ret = (ret + alignment - 1) & ~(alignment - 1);
    }
    TRACE("(%p) Returning %d\n", This, ret);
    return ret;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetOverlayPosition(IWineD3DSurface *iface, LONG X, LONG Y) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    LONG w, h;

    TRACE("(%p)->(%d,%d) Stub!\n", This, X, Y);

    if(!(This->resource.usage & WINED3DUSAGE_OVERLAY))
    {
        TRACE("(%p): Not an overlay surface\n", This);
        return WINEDDERR_NOTAOVERLAYSURFACE;
    }

    w = This->overlay_destrect.right - This->overlay_destrect.left;
    h = This->overlay_destrect.bottom - This->overlay_destrect.top;
    This->overlay_destrect.left = X;
    This->overlay_destrect.top = Y;
    This->overlay_destrect.right = X + w;
    This->overlay_destrect.bottom = Y + h;

    IWineD3DSurface_DrawOverlay(iface);

    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetOverlayPosition(IWineD3DSurface *iface, LONG *X, LONG *Y) {
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    HRESULT hr;

    TRACE("(%p)->(%p,%p)\n", This, X, Y);

    if(!(This->resource.usage & WINED3DUSAGE_OVERLAY))
    {
        TRACE("(%p): Not an overlay surface\n", This);
        return WINEDDERR_NOTAOVERLAYSURFACE;
    }

    if (!This->overlay_dest)
    {
        *X = 0; *Y = 0;
        hr = WINEDDERR_OVERLAYNOTVISIBLE;
    } else {
        *X = This->overlay_destrect.left;
        *Y = This->overlay_destrect.top;
        hr = WINED3D_OK;
    }

    TRACE("Returning 0x%08x, position %d, %d\n", hr, *X, *Y);
    return hr;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_UpdateOverlayZOrder(IWineD3DSurface *iface, DWORD flags, IWineD3DSurface *Ref)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;

    FIXME("iface %p, flags %#x, ref %p stub!\n", iface, flags, Ref);

    if(!(This->resource.usage & WINED3DUSAGE_OVERLAY))
    {
        TRACE("(%p): Not an overlay surface\n", This);
        return WINEDDERR_NOTAOVERLAYSURFACE;
    }

    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_UpdateOverlay(IWineD3DSurface *iface, const RECT *SrcRect,
        IWineD3DSurface *DstSurface, const RECT *DstRect, DWORD flags, const WINEDDOVERLAYFX *FX)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    IWineD3DSurfaceImpl *Dst = (IWineD3DSurfaceImpl *) DstSurface;

    TRACE("iface %p, src_rect %s, dst_surface %p, dst_rect %s, flags %#x, fx %p.\n",
            iface, wine_dbgstr_rect(SrcRect), DstSurface, wine_dbgstr_rect(DstRect), flags, FX);

    if(!(This->resource.usage & WINED3DUSAGE_OVERLAY))
    {
        WARN("(%p): Not an overlay surface\n", This);
        return WINEDDERR_NOTAOVERLAYSURFACE;
    } else if(!DstSurface) {
        WARN("(%p): Dest surface is NULL\n", This);
        return WINED3DERR_INVALIDCALL;
    }

    if(SrcRect) {
        This->overlay_srcrect = *SrcRect;
    } else {
        This->overlay_srcrect.left = 0;
        This->overlay_srcrect.top = 0;
        This->overlay_srcrect.right = This->currentDesc.Width;
        This->overlay_srcrect.bottom = This->currentDesc.Height;
    }

    if(DstRect) {
        This->overlay_destrect = *DstRect;
    } else {
        This->overlay_destrect.left = 0;
        This->overlay_destrect.top = 0;
        This->overlay_destrect.right = Dst ? Dst->currentDesc.Width : 0;
        This->overlay_destrect.bottom = Dst ? Dst->currentDesc.Height : 0;
    }

    if (This->overlay_dest && (This->overlay_dest != Dst || flags & WINEDDOVER_HIDE))
    {
        list_remove(&This->overlay_entry);
    }

    if (flags & WINEDDOVER_SHOW)
    {
        if (This->overlay_dest != Dst)
        {
            This->overlay_dest = Dst;
            list_add_tail(&Dst->overlays, &This->overlay_entry);
        }
    }
    else if (flags & WINEDDOVER_HIDE)
    {
        /* tests show that the rectangles are erased on hide */
        This->overlay_srcrect.left   = 0; This->overlay_srcrect.top     = 0;
        This->overlay_srcrect.right  = 0; This->overlay_srcrect.bottom  = 0;
        This->overlay_destrect.left  = 0; This->overlay_destrect.top    = 0;
        This->overlay_destrect.right = 0; This->overlay_destrect.bottom = 0;
        This->overlay_dest = NULL;
    }

    IWineD3DSurface_DrawOverlay(iface);

    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetClipper(IWineD3DSurface *iface, IWineD3DClipper *clipper)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    TRACE("(%p)->(%p)\n", This, clipper);

    This->clipper = clipper;
    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_GetClipper(IWineD3DSurface *iface, IWineD3DClipper **clipper)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *) iface;
    TRACE("(%p)->(%p)\n", This, clipper);

    *clipper = This->clipper;
    if(*clipper) {
        IWineD3DClipper_AddRef(*clipper);
    }
    return WINED3D_OK;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_SetFormat(IWineD3DSurface *iface, enum wined3d_format_id format_id)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    const struct wined3d_format *format = wined3d_get_format(&This->resource.device->adapter->gl_info, format_id);

    if (This->resource.format->id != WINED3DFMT_UNKNOWN)
    {
        FIXME("(%p) : The format of the surface must be WINED3DFORMAT_UNKNOWN\n", This);
        return WINED3DERR_INVALIDCALL;
    }

    TRACE("(%p) : Setting texture format to %s (%#x).\n", This, debug_d3dformat(format_id), format_id);

    This->resource.size = wined3d_format_calculate_size(format, This->resource.device->surface_alignment,
            This->pow2Width, This->pow2Height);

    This->flags |= (WINED3DFMT_D16_LOCKABLE == format_id) ? SFLAG_LOCKABLE : 0;

    This->resource.format = format;

    TRACE("(%p) : Size %d, bytesPerPixel %d\n", This, This->resource.size, format->byte_count);

    return WINED3D_OK;
}

HRESULT IWineD3DBaseSurfaceImpl_CreateDIBSection(IWineD3DSurface *iface)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    const struct wined3d_format *format = This->resource.format;
    int extraline = 0;
    SYSTEM_INFO sysInfo;
    BITMAPINFO* b_info;
    HDC ddc;
    DWORD *masks;
    UINT usage;

    if (!(format->flags & WINED3DFMT_FLAG_GETDC))
    {
        WARN("Cannot use GetDC on a %s surface\n", debug_d3dformat(format->id));
        return WINED3DERR_INVALIDCALL;
    }

    switch (format->byte_count)
    {
        case 2:
        case 4:
            /* Allocate extra space to store the RGB bit masks. */
            b_info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BITMAPINFOHEADER) + 3 * sizeof(DWORD));
            break;

        case 3:
            b_info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BITMAPINFOHEADER));
            break;

        default:
            /* Allocate extra space for a palette. */
            b_info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                    sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * (1 << (format->byte_count * 8)));
            break;
    }

    if (!b_info)
        return E_OUTOFMEMORY;

        /* Some apps access the surface in via DWORDs, and do not take the necessary care at the end of the
    * surface. So we need at least extra 4 bytes at the end of the surface. Check against the page size,
    * if the last page used for the surface has at least 4 spare bytes we're safe, otherwise
    * add an extra line to the dib section
        */
    GetSystemInfo(&sysInfo);
    if( ((This->resource.size + 3) % sysInfo.dwPageSize) < 4) {
        extraline = 1;
        TRACE("Adding an extra line to the dib section\n");
    }

    b_info->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    /* TODO: Is there a nicer way to force a specific alignment? (8 byte for ddraw) */
    b_info->bmiHeader.biWidth = IWineD3DSurface_GetPitch(iface) / format->byte_count;
    b_info->bmiHeader.biHeight = -This->currentDesc.Height -extraline;
    b_info->bmiHeader.biSizeImage = ( This->currentDesc.Height + extraline) * IWineD3DSurface_GetPitch(iface);
    b_info->bmiHeader.biPlanes = 1;
    b_info->bmiHeader.biBitCount = format->byte_count * 8;

    b_info->bmiHeader.biXPelsPerMeter = 0;
    b_info->bmiHeader.biYPelsPerMeter = 0;
    b_info->bmiHeader.biClrUsed = 0;
    b_info->bmiHeader.biClrImportant = 0;

    /* Get the bit masks */
    masks = (DWORD *)b_info->bmiColors;
    switch (This->resource.format->id)
    {
        case WINED3DFMT_B8G8R8_UNORM:
            usage = DIB_RGB_COLORS;
            b_info->bmiHeader.biCompression = BI_RGB;
            break;

        case WINED3DFMT_B5G5R5X1_UNORM:
        case WINED3DFMT_B5G5R5A1_UNORM:
        case WINED3DFMT_B4G4R4A4_UNORM:
        case WINED3DFMT_B4G4R4X4_UNORM:
        case WINED3DFMT_B2G3R3_UNORM:
        case WINED3DFMT_B2G3R3A8_UNORM:
        case WINED3DFMT_R10G10B10A2_UNORM:
        case WINED3DFMT_R8G8B8A8_UNORM:
        case WINED3DFMT_R8G8B8X8_UNORM:
        case WINED3DFMT_B10G10R10A2_UNORM:
        case WINED3DFMT_B5G6R5_UNORM:
        case WINED3DFMT_R16G16B16A16_UNORM:
            usage = 0;
            b_info->bmiHeader.biCompression = BI_BITFIELDS;
            masks[0] = format->red_mask;
            masks[1] = format->green_mask;
            masks[2] = format->blue_mask;
            break;

        default:
            /* Don't know palette */
            b_info->bmiHeader.biCompression = BI_RGB;
            usage = 0;
            break;
    }

    if (!(ddc = GetDC(0)))
    {
        HeapFree(GetProcessHeap(), 0, b_info);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    TRACE("Creating a DIB section with size %dx%dx%d, size=%d\n", b_info->bmiHeader.biWidth, b_info->bmiHeader.biHeight, b_info->bmiHeader.biBitCount, b_info->bmiHeader.biSizeImage);
    This->dib.DIBsection = CreateDIBSection(ddc, b_info, usage, &This->dib.bitmap_data, 0 /* Handle */, 0 /* Offset */);
    ReleaseDC(0, ddc);

    if (!This->dib.DIBsection) {
        ERR("CreateDIBSection failed!\n");
        HeapFree(GetProcessHeap(), 0, b_info);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    TRACE("DIBSection at : %p\n", This->dib.bitmap_data);
    /* copy the existing surface to the dib section */
    if(This->resource.allocatedMemory) {
        memcpy(This->dib.bitmap_data, This->resource.allocatedMemory,  This->currentDesc.Height * IWineD3DSurface_GetPitch(iface));
    } else {
        /* This is to make LockRect read the gl Texture although memory is allocated */
        This->flags &= ~SFLAG_INSYSMEM;
    }
    This->dib.bitmap_size = b_info->bmiHeader.biSizeImage;

    HeapFree(GetProcessHeap(), 0, b_info);

    /* Now allocate a HDC */
    This->hDC = CreateCompatibleDC(0);
    This->dib.holdbitmap = SelectObject(This->hDC, This->dib.DIBsection);
    TRACE("using wined3d palette %p\n", This->palette);
    SelectPalette(This->hDC,
                  This->palette ? This->palette->hpal : 0,
                  FALSE);

    This->flags |= SFLAG_DIBSECTION;

    HeapFree(GetProcessHeap(), 0, This->resource.heapMemory);
    This->resource.heapMemory = NULL;

    return WINED3D_OK;
}

static void convert_r32_float_r16_float(const BYTE *src, BYTE *dst, DWORD pitch_in, DWORD pitch_out,
                              unsigned int w, unsigned int h)
{
    unsigned int x, y;
    const float *src_f;
    unsigned short *dst_s;

    TRACE("Converting %dx%d pixels, pitches %d %d\n", w, h, pitch_in, pitch_out);
    for(y = 0; y < h; y++) {
        src_f = (const float *)(src + y * pitch_in);
        dst_s = (unsigned short *) (dst + y * pitch_out);
        for(x = 0; x < w; x++) {
            dst_s[x] = float_32_to_16(src_f + x);
        }
    }
}

static void convert_r5g6b5_x8r8g8b8(const BYTE *src, BYTE *dst,
        DWORD pitch_in, DWORD pitch_out, unsigned int w, unsigned int h)
{
    static const unsigned char convert_5to8[] =
    {
        0x00, 0x08, 0x10, 0x19, 0x21, 0x29, 0x31, 0x3a,
        0x42, 0x4a, 0x52, 0x5a, 0x63, 0x6b, 0x73, 0x7b,
        0x84, 0x8c, 0x94, 0x9c, 0xa5, 0xad, 0xb5, 0xbd,
        0xc5, 0xce, 0xd6, 0xde, 0xe6, 0xef, 0xf7, 0xff,
    };
    static const unsigned char convert_6to8[] =
    {
        0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c,
        0x20, 0x24, 0x28, 0x2d, 0x31, 0x35, 0x39, 0x3d,
        0x41, 0x45, 0x49, 0x4d, 0x51, 0x55, 0x59, 0x5d,
        0x61, 0x65, 0x69, 0x6d, 0x71, 0x75, 0x79, 0x7d,
        0x82, 0x86, 0x8a, 0x8e, 0x92, 0x96, 0x9a, 0x9e,
        0xa2, 0xa6, 0xaa, 0xae, 0xb2, 0xb6, 0xba, 0xbe,
        0xc2, 0xc6, 0xca, 0xce, 0xd2, 0xd7, 0xdb, 0xdf,
        0xe3, 0xe7, 0xeb, 0xef, 0xf3, 0xf7, 0xfb, 0xff,
    };
    unsigned int x, y;

    TRACE("Converting %ux%u pixels, pitches %u %u\n", w, h, pitch_in, pitch_out);

    for (y = 0; y < h; ++y)
    {
        const WORD *src_line = (const WORD *)(src + y * pitch_in);
        DWORD *dst_line = (DWORD *)(dst + y * pitch_out);
        for (x = 0; x < w; ++x)
        {
            WORD pixel = src_line[x];
            dst_line[x] = 0xff000000
                    | convert_5to8[(pixel & 0xf800) >> 11] << 16
                    | convert_6to8[(pixel & 0x07e0) >> 5] << 8
                    | convert_5to8[(pixel & 0x001f)];
        }
    }
}

static void convert_a8r8g8b8_x8r8g8b8(const BYTE *src, BYTE *dst,
        DWORD pitch_in, DWORD pitch_out, unsigned int w, unsigned int h)
{
    unsigned int x, y;

    TRACE("Converting %ux%u pixels, pitches %u %u\n", w, h, pitch_in, pitch_out);

    for (y = 0; y < h; ++y)
    {
        const DWORD *src_line = (const DWORD *)(src + y * pitch_in);
        DWORD *dst_line = (DWORD *)(dst + y * pitch_out);

        for (x = 0; x < w; ++x)
        {
            dst_line[x] = 0xff000000 | (src_line[x] & 0xffffff);
        }
    }
}

static inline BYTE cliptobyte(int x)
{
    return (BYTE) ((x < 0) ? 0 : ((x > 255) ? 255 : x));
}

static void convert_yuy2_x8r8g8b8(const BYTE *src, BYTE *dst,
        DWORD pitch_in, DWORD pitch_out, unsigned int w, unsigned int h)
{
    unsigned int x, y;
    int c2, d, e, r2 = 0, g2 = 0, b2 = 0;

    TRACE("Converting %ux%u pixels, pitches %u %u\n", w, h, pitch_in, pitch_out);

    for (y = 0; y < h; ++y)
    {
        const BYTE *src_line = src + y * pitch_in;
        DWORD *dst_line = (DWORD *)(dst + y * pitch_out);
        for (x = 0; x < w; ++x)
        {
            /* YUV to RGB conversion formulas from http://en.wikipedia.org/wiki/YUV:
             *     C = Y - 16; D = U - 128; E = V - 128;
             *     R = cliptobyte((298 * C + 409 * E + 128) >> 8);
             *     G = cliptobyte((298 * C - 100 * D - 208 * E + 128) >> 8);
             *     B = cliptobyte((298 * C + 516 * D + 128) >> 8);
             * Two adjacent YUY2 pixels are stored as four bytes: Y0 U Y1 V .
             * U and V are shared between the pixels.
             */
            if (!(x & 1))         /* for every even pixel, read new U and V */
            {
                d = (int) src_line[1] - 128;
                e = (int) src_line[3] - 128;
                r2 = 409 * e + 128;
                g2 = - 100 * d - 208 * e + 128;
                b2 = 516 * d + 128;
            }
            c2 = 298 * ((int) src_line[0] - 16);
            dst_line[x] = 0xff000000
                | cliptobyte((c2 + r2) >> 8) << 16    /* red   */
                | cliptobyte((c2 + g2) >> 8) << 8     /* green */
                | cliptobyte((c2 + b2) >> 8);         /* blue  */
                /* Scale RGB values to 0..255 range,
                 * then clip them if still not in range (may be negative),
                 * then shift them within DWORD if necessary.
                 */
            src_line += 2;
        }
    }
}

struct d3dfmt_convertor_desc
{
    enum wined3d_format_id from, to;
    void (*convert)(const BYTE *src, BYTE *dst, DWORD pitch_in, DWORD pitch_out, unsigned int w, unsigned int h);
};

static const struct d3dfmt_convertor_desc convertors[] =
{
    {WINED3DFMT_R32_FLOAT,      WINED3DFMT_R16_FLOAT,       convert_r32_float_r16_float},
    {WINED3DFMT_B5G6R5_UNORM,   WINED3DFMT_B8G8R8X8_UNORM,  convert_r5g6b5_x8r8g8b8},
    {WINED3DFMT_B8G8R8A8_UNORM, WINED3DFMT_B8G8R8X8_UNORM,  convert_a8r8g8b8_x8r8g8b8},
    {WINED3DFMT_YUY2,           WINED3DFMT_B8G8R8X8_UNORM,  convert_yuy2_x8r8g8b8},
};

static inline const struct d3dfmt_convertor_desc *find_convertor(enum wined3d_format_id from, enum wined3d_format_id to)
{
    unsigned int i;
    for(i = 0; i < (sizeof(convertors) / sizeof(convertors[0])); i++) {
        if(convertors[i].from == from && convertors[i].to == to) {
            return &convertors[i];
        }
    }
    return NULL;
}

/*****************************************************************************
 * surface_convert_format
 *
 * Creates a duplicate of a surface in a different format. Is used by Blt to
 * blit between surfaces with different formats
 *
 * Parameters
 *  source: Source surface
 *  fmt: Requested destination format
 *
 *****************************************************************************/
static IWineD3DSurfaceImpl *surface_convert_format(IWineD3DSurfaceImpl *source, enum wined3d_format_id to_fmt)
{
    IWineD3DSurface *ret = NULL;
    const struct d3dfmt_convertor_desc *conv;
    WINED3DLOCKED_RECT lock_src, lock_dst;
    HRESULT hr;

    conv = find_convertor(source->resource.format->id, to_fmt);
    if (!conv)
    {
        FIXME("Cannot find a conversion function from format %s to %s.\n",
                debug_d3dformat(source->resource.format->id), debug_d3dformat(to_fmt));
        return NULL;
    }

    IWineD3DDevice_CreateSurface((IWineD3DDevice *)source->resource.device, source->currentDesc.Width,
            source->currentDesc.Height, to_fmt, TRUE /* lockable */, TRUE /* discard  */, 0 /* level */,
            0 /* usage */, WINED3DPOOL_SCRATCH, WINED3DMULTISAMPLE_NONE /* TODO: Multisampled conversion */,
            0 /* MultiSampleQuality */, IWineD3DSurface_GetImplType((IWineD3DSurface *) source),
            NULL /* parent */, &wined3d_null_parent_ops, &ret);
    if(!ret) {
        ERR("Failed to create a destination surface for conversion\n");
        return NULL;
    }

    memset(&lock_src, 0, sizeof(lock_src));
    memset(&lock_dst, 0, sizeof(lock_dst));

    hr = IWineD3DSurface_Map((IWineD3DSurface *)source, &lock_src, NULL, WINED3DLOCK_READONLY);
    if (FAILED(hr))
    {
        ERR("Failed to lock the source surface.\n");
        IWineD3DSurface_Release(ret);
        return NULL;
    }
    hr = IWineD3DSurface_Map(ret, &lock_dst, NULL, WINED3DLOCK_READONLY);
    if (FAILED(hr))
    {
        ERR("Failed to lock the dest surface\n");
        IWineD3DSurface_Unmap((IWineD3DSurface *)source);
        IWineD3DSurface_Release(ret);
        return NULL;
    }

    conv->convert(lock_src.pBits, lock_dst.pBits, lock_src.Pitch, lock_dst.Pitch,
                  source->currentDesc.Width, source->currentDesc.Height);

    IWineD3DSurface_Unmap(ret);
    IWineD3DSurface_Unmap((IWineD3DSurface *)source);

    return (IWineD3DSurfaceImpl *) ret;
}

/*****************************************************************************
 * _Blt_ColorFill
 *
 * Helper function that fills a memory area with a specific color
 *
 * Params:
 *  buf: memory address to start filling at
 *  width, height: Dimensions of the area to fill
 *  bpp: Bit depth of the surface
 *  lPitch: pitch of the surface
 *  color: Color to fill with
 *
 *****************************************************************************/
static HRESULT
        _Blt_ColorFill(BYTE *buf,
                       int width, int height,
                       int bpp, LONG lPitch,
                       DWORD color)
{
    int x, y;
    LPBYTE first;

    /* Do first row */

#define COLORFILL_ROW(type) \
    { \
    type *d = (type *) buf; \
    for (x = 0; x < width; x++) \
    d[x] = (type) color; \
    break; \
}
    switch(bpp)
    {
        case 1: COLORFILL_ROW(BYTE)
                case 2: COLORFILL_ROW(WORD)
        case 3:
        {
            BYTE *d = buf;
            for (x = 0; x < width; x++,d+=3)
            {
                d[0] = (color    ) & 0xFF;
                d[1] = (color>> 8) & 0xFF;
                d[2] = (color>>16) & 0xFF;
            }
            break;
        }
        case 4: COLORFILL_ROW(DWORD)
        default:
            FIXME("Color fill not implemented for bpp %d!\n", bpp*8);
            return WINED3DERR_NOTAVAILABLE;
    }

#undef COLORFILL_ROW

    /* Now copy first row */
    first = buf;
    for (y = 1; y < height; y++)
    {
        buf += lPitch;
        memcpy(buf, first, width * bpp);
    }
    return WINED3D_OK;
}

/*****************************************************************************
 * IWineD3DSurface::Blt, SW emulation version
 *
 * Performs a blit to a surface, with or without a source surface.
 * This is the main functionality of DirectDraw
 *
 * Params:
 *  DestRect: Destination rectangle to write to
 *  src_surface: Source surface, can be NULL
 *  SrcRect: Source rectangle
 *****************************************************************************/
HRESULT WINAPI IWineD3DBaseSurfaceImpl_Blt(IWineD3DSurface *iface, const RECT *DestRect, IWineD3DSurface *src_surface,
        const RECT *SrcRect, DWORD flags, const WINEDDBLTFX *DDBltFx, WINED3DTEXTUREFILTERTYPE Filter)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    IWineD3DSurfaceImpl *src = (IWineD3DSurfaceImpl *)src_surface;
    RECT        xdst,xsrc;
    HRESULT     ret = WINED3D_OK;
    WINED3DLOCKED_RECT  dlock, slock;
    int bpp, srcheight, srcwidth, dstheight, dstwidth, width;
    const struct wined3d_format *sEntry, *dEntry;
    int x, y;
    const BYTE *sbuf;
    BYTE *dbuf;

    TRACE("iface %p, dst_rect %s, src_surface %p, src_rect %s, flags %#x, fx %p, filter %s.\n",
            iface, wine_dbgstr_rect(DestRect), src_surface, wine_dbgstr_rect(SrcRect),
            flags, DDBltFx, debug_d3dtexturefiltertype(Filter));

    if ((This->flags & SFLAG_LOCKED) || (src && (src->flags & SFLAG_LOCKED)))
    {
        WARN(" Surface is busy, returning DDERR_SURFACEBUSY\n");
        return WINEDDERR_SURFACEBUSY;
    }

    /* First check for the validity of source / destination rectangles.
     * This was verified using a test application + by MSDN. */

    if (SrcRect)
    {
        if (src)
        {
            if (SrcRect->right < SrcRect->left || SrcRect->bottom < SrcRect->top
                    || SrcRect->left > src->currentDesc.Width || SrcRect->left < 0
                    || SrcRect->top > src->currentDesc.Height || SrcRect->top < 0
                    || SrcRect->right > src->currentDesc.Width || SrcRect->right < 0
                    || SrcRect->bottom > src->currentDesc.Height || SrcRect->bottom < 0)
            {
                WARN("Application gave us bad source rectangle for Blt.\n");
                return WINEDDERR_INVALIDRECT;
            }

            if (!SrcRect->right || !SrcRect->bottom
                    || SrcRect->left == (int)src->currentDesc.Width
                    || SrcRect->top == (int)src->currentDesc.Height)
            {
                TRACE("Nothing to be done.\n");
                return WINED3D_OK;
            }
        }

        xsrc = *SrcRect;
    }
    else if (src)
    {
        xsrc.left = 0;
        xsrc.top = 0;
        xsrc.right = src->currentDesc.Width;
        xsrc.bottom = src->currentDesc.Height;
    }
    else
    {
        memset(&xsrc, 0, sizeof(xsrc));
    }

    if (DestRect)
    {
        /* For the Destination rect, it can be out of bounds on the condition
         * that a clipper is set for the given surface. */
        if (!This->clipper && (DestRect->right < DestRect->left || DestRect->bottom < DestRect->top
                || DestRect->left > This->currentDesc.Width || DestRect->left < 0
                || DestRect->top > This->currentDesc.Height || DestRect->top < 0
                || DestRect->right > This->currentDesc.Width || DestRect->right < 0
                || DestRect->bottom > This->currentDesc.Height || DestRect->bottom < 0))
        {
            WARN("Application gave us bad destination rectangle for Blt without a clipper set.\n");
            return WINEDDERR_INVALIDRECT;
        }

        if (DestRect->right <= 0 || DestRect->bottom <= 0
                || DestRect->left >= (int)This->currentDesc.Width
                || DestRect->top >= (int)This->currentDesc.Height)
        {
            TRACE("Nothing to be done.\n");
            return WINED3D_OK;
        }

        if (!src)
        {
            RECT full_rect;

            full_rect.left = 0;
            full_rect.top = 0;
            full_rect.right = This->currentDesc.Width;
            full_rect.bottom = This->currentDesc.Height;
            IntersectRect(&xdst, &full_rect, DestRect);
        }
        else
        {
            BOOL clip_horiz, clip_vert;

            xdst = *DestRect;
            clip_horiz = xdst.left < 0 || xdst.right > (int)This->currentDesc.Width;
            clip_vert = xdst.top < 0 || xdst.bottom > (int)This->currentDesc.Height;

            if (clip_vert || clip_horiz)
            {
                /* Now check if this is a special case or not... */
                if ((flags & WINEDDBLT_DDFX)
                        || (clip_horiz && xdst.right - xdst.left != xsrc.right - xsrc.left)
                        || (clip_vert && xdst.bottom - xdst.top != xsrc.bottom - xsrc.top))
                {
                    WARN("Out of screen rectangle in special case. Not handled right now.\n");
                    return WINED3D_OK;
                }

                if (clip_horiz)
                {
                    if (xdst.left < 0)
                    {
                        xsrc.left -= xdst.left;
                        xdst.left = 0;
                    }
                    if (xdst.right > This->currentDesc.Width)
                    {
                        xsrc.right -= (xdst.right - (int)This->currentDesc.Width);
                        xdst.right = (int)This->currentDesc.Width;
                    }
                }

                if (clip_vert)
                {
                    if (xdst.top < 0)
                    {
                        xsrc.top -= xdst.top;
                        xdst.top = 0;
                    }
                    if (xdst.bottom > This->currentDesc.Height)
                    {
                        xsrc.bottom -= (xdst.bottom - (int)This->currentDesc.Height);
                        xdst.bottom = (int)This->currentDesc.Height;
                    }
                }

                /* And check if after clipping something is still to be done... */
                if ((xdst.right <= 0) || (xdst.bottom <= 0)
                        || (xdst.left >= (int)This->currentDesc.Width)
                        || (xdst.top >= (int)This->currentDesc.Height)
                        || (xsrc.right <= 0) || (xsrc.bottom <= 0)
                        || (xsrc.left >= (int)src->currentDesc.Width)
                        || (xsrc.top >= (int)src->currentDesc.Height))
                {
                    TRACE("Nothing to be done after clipping.\n");
                    return WINED3D_OK;
                }
            }
        }
    }
    else
    {
        xdst.left = 0;
        xdst.top = 0;
        xdst.right = This->currentDesc.Width;
        xdst.bottom = This->currentDesc.Height;
    }

    if (src == This)
    {
        IWineD3DSurface_Map(iface, &dlock, NULL, 0);
        slock = dlock;
        sEntry = This->resource.format;
        dEntry = sEntry;
    }
    else
    {
        dEntry = This->resource.format;
        if (src)
        {
            if (This->resource.format->id != src->resource.format->id)
            {
                src = surface_convert_format(src, dEntry->id);
                if (!src)
                {
                    /* The conv function writes a FIXME */
                    WARN("Cannot convert source surface format to dest format\n");
                    goto release;
                }
            }
            IWineD3DSurface_Map((IWineD3DSurface *)src, &slock, NULL, WINED3DLOCK_READONLY);
            sEntry = src->resource.format;
        }
        else
        {
            sEntry = dEntry;
        }
        if (DestRect)
            IWineD3DSurface_Map(iface, &dlock, &xdst, 0);
        else
            IWineD3DSurface_Map(iface, &dlock, NULL, 0);
    }

    if (!DDBltFx || !(DDBltFx->dwDDFX)) flags &= ~WINEDDBLT_DDFX;

    if (sEntry->flags & dEntry->flags & WINED3DFMT_FLAG_FOURCC)
    {
        if (!DestRect || src == This)
        {
            memcpy(dlock.pBits, slock.pBits, This->resource.size);
            goto release;
        }
    }

    bpp = This->resource.format->byte_count;
    srcheight = xsrc.bottom - xsrc.top;
    srcwidth = xsrc.right - xsrc.left;
    dstheight = xdst.bottom - xdst.top;
    dstwidth = xdst.right - xdst.left;
    width = (xdst.right - xdst.left) * bpp;

    if (DestRect && src != This)
        dbuf = dlock.pBits;
    else
        dbuf = (BYTE*)dlock.pBits+(xdst.top*dlock.Pitch)+(xdst.left*bpp);

    if (flags & WINEDDBLT_WAIT)
    {
        flags &= ~WINEDDBLT_WAIT;
    }
    if (flags & WINEDDBLT_ASYNC)
    {
        static BOOL displayed = FALSE;
        if (!displayed)
            FIXME("Can't handle WINEDDBLT_ASYNC flag right now.\n");
        displayed = TRUE;
        flags &= ~WINEDDBLT_ASYNC;
    }
    if (flags & WINEDDBLT_DONOTWAIT)
    {
        /* WINEDDBLT_DONOTWAIT appeared in DX7 */
        static BOOL displayed = FALSE;
        if (!displayed)
            FIXME("Can't handle WINEDDBLT_DONOTWAIT flag right now.\n");
        displayed = TRUE;
        flags &= ~WINEDDBLT_DONOTWAIT;
    }

    /* First, all the 'source-less' blits */
    if (flags & WINEDDBLT_COLORFILL)
    {
        ret = _Blt_ColorFill(dbuf, dstwidth, dstheight, bpp,
                             dlock.Pitch, DDBltFx->u5.dwFillColor);
        flags &= ~WINEDDBLT_COLORFILL;
    }

    if (flags & WINEDDBLT_DEPTHFILL)
    {
        FIXME("DDBLT_DEPTHFILL needs to be implemented!\n");
    }
    if (flags & WINEDDBLT_ROP)
    {
        /* Catch some degenerate cases here */
        switch(DDBltFx->dwROP)
        {
            case BLACKNESS:
                ret = _Blt_ColorFill(dbuf,dstwidth,dstheight,bpp,dlock.Pitch,0);
                break;
                case 0xAA0029: /* No-op */
                    break;
            case WHITENESS:
                ret = _Blt_ColorFill(dbuf,dstwidth,dstheight,bpp,dlock.Pitch,~0);
                break;
                case SRCCOPY: /* well, we do that below ? */
                    break;
            default:
                FIXME("Unsupported raster op: %08x  Pattern: %p\n", DDBltFx->dwROP, DDBltFx->u5.lpDDSPattern);
                goto error;
        }
        flags &= ~WINEDDBLT_ROP;
    }
    if (flags & WINEDDBLT_DDROPS)
    {
        FIXME("\tDdraw Raster Ops: %08x  Pattern: %p\n", DDBltFx->dwDDROP, DDBltFx->u5.lpDDSPattern);
    }
    /* Now the 'with source' blits */
    if (src)
    {
        const BYTE *sbase;
        int sx, xinc, sy, yinc;

        if (!dstwidth || !dstheight) /* hmm... stupid program ? */
            goto release;

        if (Filter != WINED3DTEXF_NONE && Filter != WINED3DTEXF_POINT
                && (srcwidth != dstwidth || srcheight != dstheight))
        {
            /* Can happen when d3d9 apps do a StretchRect call which isn't handled in gl */
            FIXME("Filter %s not supported in software blit.\n", debug_d3dtexturefiltertype(Filter));
        }

        sbase = (BYTE*)slock.pBits+(xsrc.top*slock.Pitch)+xsrc.left*bpp;
        xinc = (srcwidth << 16) / dstwidth;
        yinc = (srcheight << 16) / dstheight;

        if (!flags)
        {
            /* No effects, we can cheat here */
            if (dstwidth == srcwidth)
            {
                if (dstheight == srcheight)
                {
                    /* No stretching in either direction. This needs to be as
                    * fast as possible */
                    sbuf = sbase;

                    /* check for overlapping surfaces */
                    if (src != This || xdst.top < xsrc.top ||
                        xdst.right <= xsrc.left || xsrc.right <= xdst.left)
                    {
                        /* no overlap, or dst above src, so copy from top downwards */
                        for (y = 0; y < dstheight; y++)
                        {
                            memcpy(dbuf, sbuf, width);
                            sbuf += slock.Pitch;
                            dbuf += dlock.Pitch;
                        }
                    }
                    else if (xdst.top > xsrc.top)  /* copy from bottom upwards */
                    {
                        sbuf += (slock.Pitch*dstheight);
                        dbuf += (dlock.Pitch*dstheight);
                        for (y = 0; y < dstheight; y++)
                        {
                            sbuf -= slock.Pitch;
                            dbuf -= dlock.Pitch;
                            memcpy(dbuf, sbuf, width);
                        }
                    }
                    else /* src and dst overlapping on the same line, use memmove */
                    {
                        for (y = 0; y < dstheight; y++)
                        {
                            memmove(dbuf, sbuf, width);
                            sbuf += slock.Pitch;
                            dbuf += dlock.Pitch;
                        }
                    }
                } else {
                    /* Stretching in Y direction only */
                    for (y = sy = 0; y < dstheight; y++, sy += yinc) {
                        sbuf = sbase + (sy >> 16) * slock.Pitch;
                        memcpy(dbuf, sbuf, width);
                        dbuf += dlock.Pitch;
                    }
                }
            }
            else
            {
                /* Stretching in X direction */
                int last_sy = -1;
                for (y = sy = 0; y < dstheight; y++, sy += yinc)
                {
                    sbuf = sbase + (sy >> 16) * slock.Pitch;

                    if ((sy >> 16) == (last_sy >> 16))
                    {
                        /* this sourcerow is the same as last sourcerow -
                        * copy already stretched row
                        */
                        memcpy(dbuf, dbuf - dlock.Pitch, width);
                    }
                    else
                    {
#define STRETCH_ROW(type) { \
                        const type *s = (const type *)sbuf; \
                        type *d = (type *)dbuf; \
                        for (x = sx = 0; x < dstwidth; x++, sx += xinc) \
                        d[x] = s[sx >> 16]; \
                        break; }

                        switch(bpp)
                        {
                            case 1: STRETCH_ROW(BYTE)
                                    case 2: STRETCH_ROW(WORD)
                                            case 4: STRETCH_ROW(DWORD)
                            case 3:
                            {
                                const BYTE *s;
                                BYTE *d = dbuf;
                                for (x = sx = 0; x < dstwidth; x++, sx+= xinc)
                                {
                                    DWORD pixel;

                                    s = sbuf+3*(sx>>16);
                                    pixel = s[0]|(s[1]<<8)|(s[2]<<16);
                                    d[0] = (pixel    )&0xff;
                                    d[1] = (pixel>> 8)&0xff;
                                    d[2] = (pixel>>16)&0xff;
                                    d+=3;
                                }
                                break;
                            }
                            default:
                                FIXME("Stretched blit not implemented for bpp %d!\n", bpp*8);
                                ret = WINED3DERR_NOTAVAILABLE;
                                goto error;
                        }
#undef STRETCH_ROW
                    }
                    dbuf += dlock.Pitch;
                    last_sy = sy;
                }
            }
        }
        else
        {
            LONG dstyinc = dlock.Pitch, dstxinc = bpp;
            DWORD keylow = 0xFFFFFFFF, keyhigh = 0, keymask = 0xFFFFFFFF;
            DWORD destkeylow = 0x0, destkeyhigh = 0xFFFFFFFF, destkeymask = 0xFFFFFFFF;
            if (flags & (WINEDDBLT_KEYSRC | WINEDDBLT_KEYDEST | WINEDDBLT_KEYSRCOVERRIDE | WINEDDBLT_KEYDESTOVERRIDE))
            {
                /* The color keying flags are checked for correctness in ddraw */
                if (flags & WINEDDBLT_KEYSRC)
                {
                    keylow  = src->SrcBltCKey.dwColorSpaceLowValue;
                    keyhigh = src->SrcBltCKey.dwColorSpaceHighValue;
                }
                else  if (flags & WINEDDBLT_KEYSRCOVERRIDE)
                {
                    keylow  = DDBltFx->ddckSrcColorkey.dwColorSpaceLowValue;
                    keyhigh = DDBltFx->ddckSrcColorkey.dwColorSpaceHighValue;
                }

                if (flags & WINEDDBLT_KEYDEST)
                {
                    /* Destination color keys are taken from the source surface ! */
                    destkeylow  = src->DestBltCKey.dwColorSpaceLowValue;
                    destkeyhigh = src->DestBltCKey.dwColorSpaceHighValue;
                }
                else if (flags & WINEDDBLT_KEYDESTOVERRIDE)
                {
                    destkeylow  = DDBltFx->ddckDestColorkey.dwColorSpaceLowValue;
                    destkeyhigh = DDBltFx->ddckDestColorkey.dwColorSpaceHighValue;
                }

                if(bpp == 1)
                {
                    keymask = 0xff;
                }
                else
                {
                    keymask = sEntry->red_mask
                            | sEntry->green_mask
                            | sEntry->blue_mask;
                }
                flags &= ~(WINEDDBLT_KEYSRC | WINEDDBLT_KEYDEST | WINEDDBLT_KEYSRCOVERRIDE | WINEDDBLT_KEYDESTOVERRIDE);
            }

            if (flags & WINEDDBLT_DDFX)
            {
                LPBYTE dTopLeft, dTopRight, dBottomLeft, dBottomRight, tmp;
                LONG tmpxy;
                dTopLeft     = dbuf;
                dTopRight    = dbuf+((dstwidth-1)*bpp);
                dBottomLeft  = dTopLeft+((dstheight-1)*dlock.Pitch);
                dBottomRight = dBottomLeft+((dstwidth-1)*bpp);

                if (DDBltFx->dwDDFX & WINEDDBLTFX_ARITHSTRETCHY)
                {
                    /* I don't think we need to do anything about this flag */
                    WARN("flags=DDBLT_DDFX nothing done for WINEDDBLTFX_ARITHSTRETCHY\n");
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_MIRRORLEFTRIGHT)
                {
                    tmp          = dTopRight;
                    dTopRight    = dTopLeft;
                    dTopLeft     = tmp;
                    tmp          = dBottomRight;
                    dBottomRight = dBottomLeft;
                    dBottomLeft  = tmp;
                    dstxinc = dstxinc *-1;
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_MIRRORUPDOWN)
                {
                    tmp          = dTopLeft;
                    dTopLeft     = dBottomLeft;
                    dBottomLeft  = tmp;
                    tmp          = dTopRight;
                    dTopRight    = dBottomRight;
                    dBottomRight = tmp;
                    dstyinc = dstyinc *-1;
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_NOTEARING)
                {
                    /* I don't think we need to do anything about this flag */
                    WARN("flags=DDBLT_DDFX nothing done for WINEDDBLTFX_NOTEARING\n");
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_ROTATE180)
                {
                    tmp          = dBottomRight;
                    dBottomRight = dTopLeft;
                    dTopLeft     = tmp;
                    tmp          = dBottomLeft;
                    dBottomLeft  = dTopRight;
                    dTopRight    = tmp;
                    dstxinc = dstxinc * -1;
                    dstyinc = dstyinc * -1;
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_ROTATE270)
                {
                    tmp          = dTopLeft;
                    dTopLeft     = dBottomLeft;
                    dBottomLeft  = dBottomRight;
                    dBottomRight = dTopRight;
                    dTopRight    = tmp;
                    tmpxy   = dstxinc;
                    dstxinc = dstyinc;
                    dstyinc = tmpxy;
                    dstxinc = dstxinc * -1;
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_ROTATE90)
                {
                    tmp          = dTopLeft;
                    dTopLeft     = dTopRight;
                    dTopRight    = dBottomRight;
                    dBottomRight = dBottomLeft;
                    dBottomLeft  = tmp;
                    tmpxy   = dstxinc;
                    dstxinc = dstyinc;
                    dstyinc = tmpxy;
                    dstyinc = dstyinc * -1;
                }
                if (DDBltFx->dwDDFX & WINEDDBLTFX_ZBUFFERBASEDEST)
                {
                    /* I don't think we need to do anything about this flag */
                    WARN("flags=WINEDDBLT_DDFX nothing done for WINEDDBLTFX_ZBUFFERBASEDEST\n");
                }
                dbuf = dTopLeft;
                flags &= ~(WINEDDBLT_DDFX);
            }

#define COPY_COLORKEY_FX(type) { \
            const type *s; \
            type *d = (type *)dbuf, *dx, tmp; \
            for (y = sy = 0; y < dstheight; y++, sy += yinc) { \
            s = (const type*)(sbase + (sy >> 16) * slock.Pitch); \
            dx = d; \
            for (x = sx = 0; x < dstwidth; x++, sx += xinc) { \
            tmp = s[sx >> 16]; \
            if (((tmp & keymask) < keylow || (tmp & keymask) > keyhigh) && \
            ((dx[0] & destkeymask) >= destkeylow && (dx[0] & destkeymask) <= destkeyhigh)) { \
            dx[0] = tmp; \
        } \
            dx = (type*)(((LPBYTE)dx)+dstxinc); \
        } \
            d = (type*)(((LPBYTE)d)+dstyinc); \
        } \
            break; }

            switch (bpp) {
                case 1: COPY_COLORKEY_FX(BYTE)
                        case 2: COPY_COLORKEY_FX(WORD)
                                case 4: COPY_COLORKEY_FX(DWORD)
                case 3:
                {
                    const BYTE *s;
                    BYTE *d = dbuf, *dx;
                    for (y = sy = 0; y < dstheight; y++, sy += yinc)
                    {
                        sbuf = sbase + (sy >> 16) * slock.Pitch;
                        dx = d;
                        for (x = sx = 0; x < dstwidth; x++, sx+= xinc)
                        {
                            DWORD pixel, dpixel = 0;
                            s = sbuf+3*(sx>>16);
                            pixel = s[0]|(s[1]<<8)|(s[2]<<16);
                            dpixel = dx[0]|(dx[1]<<8)|(dx[2]<<16);
                            if (((pixel & keymask) < keylow || (pixel & keymask) > keyhigh) &&
                                  ((dpixel & keymask) >= destkeylow || (dpixel & keymask) <= keyhigh))
                            {
                                dx[0] = (pixel    )&0xff;
                                dx[1] = (pixel>> 8)&0xff;
                                dx[2] = (pixel>>16)&0xff;
                            }
                            dx+= dstxinc;
                        }
                        d += dstyinc;
                    }
                    break;
                }
                default:
                    FIXME("%s color-keyed blit not implemented for bpp %d!\n",
                          (flags & WINEDDBLT_KEYSRC) ? "Source" : "Destination", bpp*8);
                    ret = WINED3DERR_NOTAVAILABLE;
                    goto error;
#undef COPY_COLORKEY_FX
            }
        }
    }

error:
    if (flags && FIXME_ON(d3d_surface))
    {
        FIXME("\tUnsupported flags: %#x.\n", flags);
    }

release:
    IWineD3DSurface_Unmap(iface);
    if (src && src != This) IWineD3DSurface_Unmap((IWineD3DSurface *)src);
    /* Release the converted surface if any */
    if (src && src_surface != (IWineD3DSurface *)src) IWineD3DSurface_Release((IWineD3DSurface *)src);
    return ret;
}

/*****************************************************************************
 * IWineD3DSurface::BltFast, SW emulation version
 *
 * This is the software implementation of BltFast, as used by GDI surfaces
 * and as a fallback for OpenGL surfaces. This code is taken from the old
 * DirectDraw code, and was originally written by TransGaming.
 *
 * Params:
 *  dstx:
 *  dsty:
 *  src_surface: Source surface to copy from
 *  rsrc: Source rectangle
 *  trans: Some flags
 *
 * Returns:
 *  WINED3D_OK on success
 *
 *****************************************************************************/
HRESULT WINAPI IWineD3DBaseSurfaceImpl_BltFast(IWineD3DSurface *iface, DWORD dstx, DWORD dsty,
        IWineD3DSurface *src_surface, const RECT *rsrc, DWORD trans)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;
    IWineD3DSurfaceImpl *src = (IWineD3DSurfaceImpl *)src_surface;

    int                 bpp, w, h, x, y;
    WINED3DLOCKED_RECT  dlock,slock;
    HRESULT             ret = WINED3D_OK;
    RECT                rsrc2;
    RECT                lock_src, lock_dst, lock_union;
    const BYTE          *sbuf;
    BYTE                *dbuf;
    const struct wined3d_format *sEntry, *dEntry;

    TRACE("iface %p, dst_x %u, dst_y %u, src_surface %p, src_rect %s, flags %#x.\n",
            iface, dstx, dsty, src_surface, wine_dbgstr_rect(rsrc), trans);

    if ((This->flags & SFLAG_LOCKED) || (src->flags & SFLAG_LOCKED))
    {
        WARN(" Surface is busy, returning DDERR_SURFACEBUSY\n");
        return WINEDDERR_SURFACEBUSY;
    }

    if (!rsrc)
    {
        WARN("rsrc is NULL!\n");
        rsrc2.left = 0;
        rsrc2.top = 0;
        rsrc2.right = src->currentDesc.Width;
        rsrc2.bottom = src->currentDesc.Height;
        rsrc = &rsrc2;
    }

    /* Check source rect for validity. Copied from normal Blt. Fixes Baldur's Gate.*/
    if ((rsrc->bottom > src->currentDesc.Height) || (rsrc->bottom < 0)
            || (rsrc->top   > src->currentDesc.Height) || (rsrc->top    < 0)
            || (rsrc->left  > src->currentDesc.Width)  || (rsrc->left   < 0)
            || (rsrc->right > src->currentDesc.Width)  || (rsrc->right  < 0)
            || (rsrc->right < rsrc->left)              || (rsrc->bottom < rsrc->top))
    {
        WARN("Application gave us bad source rectangle for BltFast.\n");
        return WINEDDERR_INVALIDRECT;
    }

    h = rsrc->bottom - rsrc->top;
    if (h > This->currentDesc.Height-dsty) h = This->currentDesc.Height-dsty;
    if (h > src->currentDesc.Height-rsrc->top) h = src->currentDesc.Height-rsrc->top;
    if (h <= 0) return WINEDDERR_INVALIDRECT;

    w = rsrc->right - rsrc->left;
    if (w > This->currentDesc.Width-dstx) w = This->currentDesc.Width-dstx;
    if (w > src->currentDesc.Width-rsrc->left) w = src->currentDesc.Width-rsrc->left;
    if (w <= 0) return WINEDDERR_INVALIDRECT;

    /* Now compute the locking rectangle... */
    lock_src.left = rsrc->left;
    lock_src.top = rsrc->top;
    lock_src.right = lock_src.left + w;
    lock_src.bottom = lock_src.top + h;

    lock_dst.left = dstx;
    lock_dst.top = dsty;
    lock_dst.right = dstx + w;
    lock_dst.bottom = dsty + h;

    bpp = This->resource.format->byte_count;

    /* We need to lock the surfaces, or we won't get refreshes when done. */
    if (src == This)
    {
        int pitch;

        UnionRect(&lock_union, &lock_src, &lock_dst);

        /* Lock the union of the two rectangles */
        ret = IWineD3DSurface_Map(iface, &dlock, &lock_union, 0);
        if (FAILED(ret)) goto error;

        pitch = dlock.Pitch;
        slock.Pitch = dlock.Pitch;

        /* Since slock was originally copied from this surface's description, we can just reuse it */
        sbuf = This->resource.allocatedMemory + lock_src.top * pitch + lock_src.left * bpp;
        dbuf = This->resource.allocatedMemory + lock_dst.top * pitch + lock_dst.left * bpp;
        sEntry = src->resource.format;
        dEntry = sEntry;
    }
    else
    {
        ret = IWineD3DSurface_Map(src_surface, &slock, &lock_src, WINED3DLOCK_READONLY);
        if (FAILED(ret)) goto error;
        ret = IWineD3DSurface_Map(iface, &dlock, &lock_dst, 0);
        if (FAILED(ret)) goto error;

        sbuf = slock.pBits;
        dbuf = dlock.pBits;
        TRACE("Dst is at %p, Src is at %p\n", dbuf, sbuf);

        sEntry = src->resource.format;
        dEntry = This->resource.format;
    }

    /* Handle compressed surfaces first... */
    if (sEntry->flags & dEntry->flags & WINED3DFMT_FLAG_COMPRESSED)
    {
        UINT row_block_count;

        TRACE("compressed -> compressed copy\n");
        if (trans)
            FIXME("trans arg not supported when a compressed surface is involved\n");
        if (dstx || dsty)
            FIXME("offset for destination surface is not supported\n");
        if (src->resource.format->id != This->resource.format->id)
        {
            FIXME("compressed -> compressed copy only supported for the same type of surface\n");
            ret = WINED3DERR_WRONGTEXTUREFORMAT;
            goto error;
        }

        row_block_count = (w + dEntry->block_width - 1) / dEntry->block_width;
        for (y = 0; y < h; y += dEntry->block_height)
        {
            memcpy(dbuf, sbuf, row_block_count * dEntry->block_byte_count);
            dbuf += dlock.Pitch;
            sbuf += slock.Pitch;
        }

        goto error;
    }
    if ((sEntry->flags & WINED3DFMT_FLAG_COMPRESSED) && !(dEntry->flags & WINED3DFMT_FLAG_COMPRESSED))
    {
        /* TODO: Use the libtxc_dxtn.so shared library to do
         * software decompression
         */
        ERR("Software decompression not supported.\n");
        goto error;
    }

    if (trans & (WINEDDBLTFAST_SRCCOLORKEY | WINEDDBLTFAST_DESTCOLORKEY))
    {
        DWORD keylow, keyhigh;
        DWORD mask = src->resource.format->red_mask
                | src->resource.format->green_mask
                | src->resource.format->blue_mask;

        /* For some 8-bit formats like L8 and P8 color masks don't make sense */
        if(!mask && bpp==1)
            mask = 0xff;

        TRACE("Color keyed copy\n");
        if (trans & WINEDDBLTFAST_SRCCOLORKEY)
        {
            keylow  = src->SrcBltCKey.dwColorSpaceLowValue;
            keyhigh = src->SrcBltCKey.dwColorSpaceHighValue;
        }
        else
        {
            /* I'm not sure if this is correct */
            FIXME("WINEDDBLTFAST_DESTCOLORKEY not fully supported yet.\n");
            keylow  = This->DestBltCKey.dwColorSpaceLowValue;
            keyhigh = This->DestBltCKey.dwColorSpaceHighValue;
        }

#define COPYBOX_COLORKEY(type) { \
        const type *s = (const type *)sbuf; \
        type *d = (type *)dbuf; \
        type tmp; \
        for (y = 0; y < h; y++) { \
        for (x = 0; x < w; x++) { \
        tmp = s[x]; \
        if ((tmp & mask) < keylow || (tmp & mask) > keyhigh) d[x] = tmp; \
    } \
        s = (const type *)((const BYTE *)s + slock.Pitch); \
        d = (type *)((BYTE *)d + dlock.Pitch); \
    } \
        break; \
    }

        switch (bpp) {
            case 1: COPYBOX_COLORKEY(BYTE)
                    case 2: COPYBOX_COLORKEY(WORD)
                            case 4: COPYBOX_COLORKEY(DWORD)
            case 3:
            {
                const BYTE *s;
                BYTE *d;
                DWORD tmp;
                s = sbuf;
                d = dbuf;
                for (y = 0; y < h; y++)
                {
                    for (x = 0; x < w * 3; x += 3)
                    {
                        tmp = (DWORD)s[x] + ((DWORD)s[x + 1] << 8) + ((DWORD)s[x + 2] << 16);
                        if (tmp < keylow || tmp > keyhigh)
                        {
                            d[x + 0] = s[x + 0];
                            d[x + 1] = s[x + 1];
                            d[x + 2] = s[x + 2];
                        }
                    }
                    s += slock.Pitch;
                    d += dlock.Pitch;
                }
                break;
            }
            default:
                FIXME("Source color key blitting not supported for bpp %d\n",bpp*8);
                ret = WINED3DERR_NOTAVAILABLE;
                goto error;
        }
#undef COPYBOX_COLORKEY
        TRACE("Copy Done\n");
    }
    else
    {
        int width = w * bpp;
        INT sbufpitch, dbufpitch;

        TRACE("NO color key copy\n");
        /* Handle overlapping surfaces */
        if (sbuf < dbuf)
        {
            sbuf += (h - 1) * slock.Pitch;
            dbuf += (h - 1) * dlock.Pitch;
            sbufpitch = -slock.Pitch;
            dbufpitch = -dlock.Pitch;
        }
        else
        {
            sbufpitch = slock.Pitch;
            dbufpitch = dlock.Pitch;
        }
        for (y = 0; y < h; y++)
        {
            /* This is pretty easy, a line for line memcpy */
            memmove(dbuf, sbuf, width);
            sbuf += sbufpitch;
            dbuf += dbufpitch;
        }
        TRACE("Copy done\n");
    }

error:
    if (src == This)
    {
        IWineD3DSurface_Unmap(iface);
    }
    else
    {
        IWineD3DSurface_Unmap(iface);
        IWineD3DSurface_Unmap(src_surface);
    }

    return ret;
}

HRESULT WINAPI IWineD3DBaseSurfaceImpl_Map(IWineD3DSurface *iface,
        WINED3DLOCKED_RECT *pLockedRect, const RECT *pRect, DWORD flags)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;

    TRACE("iface %p, locked_rect %p, rect %s, flags %#x.\n",
            iface, pLockedRect, wine_dbgstr_rect(pRect), flags);

    pLockedRect->Pitch = IWineD3DSurface_GetPitch(iface);

    if (!pRect)
    {
        pLockedRect->pBits = This->resource.allocatedMemory;
        This->lockedRect.left   = 0;
        This->lockedRect.top    = 0;
        This->lockedRect.right  = This->currentDesc.Width;
        This->lockedRect.bottom = This->currentDesc.Height;

        TRACE("Locked Rect (%p) = l %d, t %d, r %d, b %d\n",
              &This->lockedRect, This->lockedRect.left, This->lockedRect.top,
              This->lockedRect.right, This->lockedRect.bottom);
    }
    else
    {
        const struct wined3d_format *format = This->resource.format;

        TRACE("Lock Rect (%p) = l %d, t %d, r %d, b %d\n",
              pRect, pRect->left, pRect->top, pRect->right, pRect->bottom);

        if ((format->flags & (WINED3DFMT_FLAG_COMPRESSED | WINED3DFMT_FLAG_BROKEN_PITCH)) == WINED3DFMT_FLAG_COMPRESSED)
        {
            /* Compressed textures are block based, so calculate the offset of
             * the block that contains the top-left pixel of the locked rectangle. */
            pLockedRect->pBits = This->resource.allocatedMemory
                    + ((pRect->top / format->block_height) * pLockedRect->Pitch)
                    + ((pRect->left / format->block_width) * format->block_byte_count);
        }
        else
        {
            pLockedRect->pBits = This->resource.allocatedMemory +
                    (pLockedRect->Pitch * pRect->top) +
                    (pRect->left * format->byte_count);
        }
        This->lockedRect.left   = pRect->left;
        This->lockedRect.top    = pRect->top;
        This->lockedRect.right  = pRect->right;
        This->lockedRect.bottom = pRect->bottom;
    }

    /* No dirtifying is needed for this surface implementation */
    TRACE("returning memory@%p, pitch(%d)\n", pLockedRect->pBits, pLockedRect->Pitch);

    return WINED3D_OK;
}

/* TODO: think about moving this down to resource? */
const void *WINAPI IWineD3DBaseSurfaceImpl_GetData(IWineD3DSurface *iface)
{
    IWineD3DSurfaceImpl *This = (IWineD3DSurfaceImpl *)iface;

    /* This should only be called for sysmem textures, it may be a good idea
     * to extend this to all pools at some point in the future  */
    if (This->resource.pool != WINED3DPOOL_SYSTEMMEM)
    {
        FIXME("(%p) Attempting to get system memory for a non-system memory texture\n", iface);
    }
    return This->resource.allocatedMemory;
}
