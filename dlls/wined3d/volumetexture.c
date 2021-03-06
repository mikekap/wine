/*
 * IWineD3DVolumeTexture implementation
 *
 * Copyright 2002-2005 Jason Edmeades
 * Copyright 2002-2005 Raphael Junqueira
 * Copyright 2005 Oliver Stieber
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
#include "wined3d_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d_texture);

/* Context activation is done by the caller. */
static HRESULT volumetexture_bind(IWineD3DBaseTextureImpl *texture, BOOL srgb)
{
    BOOL dummy;

    TRACE("texture %p, srgb %#x.\n", texture, srgb);

    return basetexture_bind(texture, srgb, &dummy);
}

/* Do not call while under the GL lock. */
static void volumetexture_preload(IWineD3DBaseTextureImpl *texture, enum WINED3DSRGB srgb)
{
    IWineD3DDeviceImpl *device = texture->resource.device;
    const struct wined3d_gl_info *gl_info = &device->adapter->gl_info;
    struct wined3d_context *context = NULL;
    BOOL srgb_mode = texture->baseTexture.is_srgb;
    BOOL srgb_was_toggled = FALSE;
    unsigned int i;

    TRACE("texture %p, srgb %#x.\n", texture, srgb);

    if (!device->isInDraw) context = context_acquire(device, NULL);
    else if (gl_info->supported[EXT_TEXTURE_SRGB] && texture->baseTexture.bindCount > 0)
    {
        srgb_mode = device->stateBlock->state.sampler_states[texture->baseTexture.sampler][WINED3DSAMP_SRGBTEXTURE];
        srgb_was_toggled = texture->baseTexture.is_srgb != srgb_mode;
        texture->baseTexture.is_srgb = srgb_mode;
    }

    /* If the texture is marked dirty or the srgb sampler setting has changed
     * since the last load then reload the volumes. */
    if (texture->baseTexture.texture_rgb.dirty)
    {
        for (i = 0; i < texture->baseTexture.level_count; ++i)
        {
            IWineD3DVolume *volume = (IWineD3DVolume *)texture->baseTexture.sub_resources[i];
            IWineD3DVolume_LoadTexture(volume, i, srgb_mode);
        }
    }
    else if (srgb_was_toggled)
    {
        for (i = 0; i < texture->baseTexture.level_count; ++i)
        {
            IWineD3DVolume *volume = (IWineD3DVolume *)texture->baseTexture.sub_resources[i];
            volume_add_dirty_box(volume, NULL);
            IWineD3DVolume_LoadTexture(volume, i, srgb_mode);
        }
    }
    else
    {
        TRACE("Texture %p not dirty, nothing to do.\n", texture);
    }

    if (context) context_release(context);

    /* No longer dirty */
    texture->baseTexture.texture_rgb.dirty = FALSE;
}

const struct wined3d_texture_ops volumetexture_ops =
{
    volumetexture_bind,
    volumetexture_preload,
};

static void volumetexture_cleanup(IWineD3DVolumeTextureImpl *This)
{
    unsigned int i;

    TRACE("(%p) : Cleaning up.\n", This);

    for (i = 0; i < This->baseTexture.level_count; ++i)
    {
        IWineD3DVolumeImpl *volume = (IWineD3DVolumeImpl *)This->baseTexture.sub_resources[i];

        if (volume)
        {
            /* Cleanup the container. */
            volume_set_container(volume, NULL);
            IWineD3DVolume_Release((IWineD3DVolume *)volume);
        }
    }
    basetexture_cleanup((IWineD3DBaseTextureImpl *)This);
}

/* *******************************************
   IWineD3DTexture IUnknown parts follow
   ******************************************* */

static HRESULT WINAPI IWineD3DVolumeTextureImpl_QueryInterface(IWineD3DVolumeTexture *iface, REFIID riid, LPVOID *ppobj)
{
    IWineD3DVolumeTextureImpl *This = (IWineD3DVolumeTextureImpl *)iface;
    TRACE("(%p)->(%s,%p)\n",This,debugstr_guid(riid),ppobj);
    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IWineD3DBase)
        || IsEqualGUID(riid, &IID_IWineD3DResource)
        || IsEqualGUID(riid, &IID_IWineD3DBaseTexture)
        || IsEqualGUID(riid, &IID_IWineD3DVolumeTexture)) {
        IUnknown_AddRef(iface);
        *ppobj = This;
        return S_OK;
    }
    *ppobj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI IWineD3DVolumeTextureImpl_AddRef(IWineD3DVolumeTexture *iface) {
    IWineD3DVolumeTextureImpl *This = (IWineD3DVolumeTextureImpl *)iface;
    TRACE("(%p) : AddRef increasing from %d\n", This, This->resource.ref);
    return InterlockedIncrement(&This->resource.ref);
}

/* Do not call while under the GL lock. */
static ULONG WINAPI IWineD3DVolumeTextureImpl_Release(IWineD3DVolumeTexture *iface) {
    IWineD3DVolumeTextureImpl *This = (IWineD3DVolumeTextureImpl *)iface;
    ULONG ref;
    TRACE("(%p) : Releasing from %d\n", This, This->resource.ref);
    ref = InterlockedDecrement(&This->resource.ref);
    if (!ref)
    {
        volumetexture_cleanup(This);
        This->resource.parent_ops->wined3d_object_destroyed(This->resource.parent);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

/* ****************************************************
   IWineD3DVolumeTexture IWineD3DResource parts follow
   **************************************************** */
static HRESULT WINAPI IWineD3DVolumeTextureImpl_SetPrivateData(IWineD3DVolumeTexture *iface,
        REFGUID riid, const void *data, DWORD data_size, DWORD flags)
{
    return resource_set_private_data((IWineD3DResourceImpl *)iface, riid, data, data_size, flags);
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_GetPrivateData(IWineD3DVolumeTexture *iface,
        REFGUID guid, void *data, DWORD *data_size)
{
    return resource_get_private_data((IWineD3DResourceImpl *)iface, guid, data, data_size);
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_FreePrivateData(IWineD3DVolumeTexture *iface, REFGUID refguid)
{
    return resource_free_private_data((IWineD3DResourceImpl *)iface, refguid);
}

static DWORD WINAPI IWineD3DVolumeTextureImpl_SetPriority(IWineD3DVolumeTexture *iface, DWORD priority)
{
    return resource_set_priority((IWineD3DResourceImpl *)iface, priority);
}

static DWORD WINAPI IWineD3DVolumeTextureImpl_GetPriority(IWineD3DVolumeTexture *iface)
{
    return resource_get_priority((IWineD3DResourceImpl *)iface);
}

static void WINAPI IWineD3DVolumeTextureImpl_PreLoad(IWineD3DVolumeTexture *iface)
{
    volumetexture_preload((IWineD3DBaseTextureImpl *)iface, SRGB_ANY);
}

/* Do not call while under the GL lock. */
static void WINAPI IWineD3DVolumeTextureImpl_UnLoad(IWineD3DVolumeTexture *iface) {
    unsigned int i;
    IWineD3DVolumeTextureImpl *This = (IWineD3DVolumeTextureImpl *)iface;
    TRACE("(%p)\n", This);

    /* Unload all the surfaces and reset the texture name. If UnLoad was called on the
     * surface before, this one will be a NOP and vice versa. Unloading an unloaded
     * surface is fine
     */
    for (i = 0; i < This->baseTexture.level_count; ++i)
    {
        IWineD3DVolume_UnLoad((IWineD3DVolume *)This->baseTexture.sub_resources[i]);
    }

    basetexture_unload((IWineD3DBaseTextureImpl *)This);
}

static WINED3DRESOURCETYPE WINAPI IWineD3DVolumeTextureImpl_GetType(IWineD3DVolumeTexture *iface)
{
    return resource_get_type((IWineD3DResourceImpl *)iface);
}

static void * WINAPI IWineD3DVolumeTextureImpl_GetParent(IWineD3DVolumeTexture *iface)
{
    TRACE("iface %p\n", iface);

    return ((IWineD3DVolumeTextureImpl *)iface)->resource.parent;
}

/* ******************************************************
   IWineD3DVolumeTexture IWineD3DBaseTexture parts follow
   ****************************************************** */
static DWORD WINAPI IWineD3DVolumeTextureImpl_SetLOD(IWineD3DVolumeTexture *iface, DWORD LODNew) {
    return basetexture_set_lod((IWineD3DBaseTextureImpl *)iface, LODNew);
}

static DWORD WINAPI IWineD3DVolumeTextureImpl_GetLOD(IWineD3DVolumeTexture *iface) {
    return basetexture_get_lod((IWineD3DBaseTextureImpl *)iface);
}

static DWORD WINAPI IWineD3DVolumeTextureImpl_GetLevelCount(IWineD3DVolumeTexture *iface)
{
    return basetexture_get_level_count((IWineD3DBaseTextureImpl *)iface);
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_SetAutoGenFilterType(IWineD3DVolumeTexture *iface,
        WINED3DTEXTUREFILTERTYPE FilterType)
{
  return basetexture_set_autogen_filter_type((IWineD3DBaseTextureImpl *)iface, FilterType);
}

static WINED3DTEXTUREFILTERTYPE WINAPI IWineD3DVolumeTextureImpl_GetAutoGenFilterType(IWineD3DVolumeTexture *iface)
{
  return basetexture_get_autogen_filter_type((IWineD3DBaseTextureImpl *)iface);
}

static void WINAPI IWineD3DVolumeTextureImpl_GenerateMipSubLevels(IWineD3DVolumeTexture *iface)
{
    basetexture_generate_mipmaps((IWineD3DBaseTextureImpl *)iface);
}

static BOOL WINAPI IWineD3DVolumeTextureImpl_IsCondNP2(IWineD3DVolumeTexture *iface)
{
    TRACE("iface %p.\n", iface);

    return FALSE;
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_GetLevelDesc(IWineD3DVolumeTexture *iface,
        UINT sub_resource_idx, WINED3DVOLUME_DESC *desc)
{
    IWineD3DBaseTextureImpl *texture = (IWineD3DBaseTextureImpl *)iface;
    IWineD3DVolume *volume;

    TRACE("iface %p, sub_resource_idx %u, desc %p.\n", iface, sub_resource_idx, desc);

    if (!(volume = (IWineD3DVolume *)basetexture_get_sub_resource(texture, sub_resource_idx)))
    {
        WARN("Failed to get sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    IWineD3DVolume_GetDesc(volume, desc);

    return WINED3D_OK;
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_GetVolumeLevel(IWineD3DVolumeTexture *iface,
        UINT sub_resource_idx, IWineD3DVolume **volume)
{
    IWineD3DBaseTextureImpl *texture = (IWineD3DBaseTextureImpl *)iface;
    IWineD3DVolume *v;

    TRACE("iface %p, sub_resource_idx %u, volume %p.\n", iface, sub_resource_idx, volume);

    if (!(v= (IWineD3DVolume *)basetexture_get_sub_resource(texture, sub_resource_idx)))
    {
        WARN("Failed to get sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    IWineD3DVolume_AddRef(v);
    *volume = v;

    TRACE("Returning volume %p.\n", *volume);

    return WINED3D_OK;
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_Map(IWineD3DVolumeTexture *iface,
        UINT sub_resource_idx, WINED3DLOCKED_BOX *locked_box, const WINED3DBOX *box, DWORD flags)
{
    IWineD3DBaseTextureImpl *texture = (IWineD3DBaseTextureImpl *)iface;
    IWineD3DVolume *volume;

    TRACE("iface %p, sub_resource_idx %u, locked_box %p, box %p, flags %#x.\n",
            iface, sub_resource_idx, locked_box, box, flags);

    if (!(volume = (IWineD3DVolume *)basetexture_get_sub_resource(texture, sub_resource_idx)))
    {
        WARN("Failed to get sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    return IWineD3DVolume_Map(volume, locked_box, box, flags);
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_Unmap(IWineD3DVolumeTexture *iface, UINT sub_resource_idx)
{
    IWineD3DBaseTextureImpl *texture = (IWineD3DBaseTextureImpl *)iface;
    IWineD3DVolume *volume;

    TRACE("iface %p, sub_resource_idx %u.\n", iface, sub_resource_idx);

    if (!(volume = (IWineD3DVolume *)basetexture_get_sub_resource(texture, sub_resource_idx)))
    {
        WARN("Failed to get sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    return IWineD3DVolume_Unmap(volume);
}

static HRESULT WINAPI IWineD3DVolumeTextureImpl_AddDirtyBox(IWineD3DVolumeTexture *iface, const WINED3DBOX *dirty_box)
{
    IWineD3DBaseTextureImpl *texture = (IWineD3DBaseTextureImpl *)iface;
    IWineD3DVolume *volume;

    TRACE("iface %p, dirty_box %p.\n", iface, dirty_box);

    if (!(volume = (IWineD3DVolume *)basetexture_get_sub_resource(texture, 0)))
    {
        WARN("Failed to get sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    texture->baseTexture.texture_rgb.dirty = TRUE;
    texture->baseTexture.texture_srgb.dirty = TRUE;
    volume_add_dirty_box(volume, dirty_box);

    return WINED3D_OK;
}

static const IWineD3DVolumeTextureVtbl IWineD3DVolumeTexture_Vtbl =
{
    /* IUnknown */
    IWineD3DVolumeTextureImpl_QueryInterface,
    IWineD3DVolumeTextureImpl_AddRef,
    IWineD3DVolumeTextureImpl_Release,
    /* resource */
    IWineD3DVolumeTextureImpl_GetParent,
    IWineD3DVolumeTextureImpl_SetPrivateData,
    IWineD3DVolumeTextureImpl_GetPrivateData,
    IWineD3DVolumeTextureImpl_FreePrivateData,
    IWineD3DVolumeTextureImpl_SetPriority,
    IWineD3DVolumeTextureImpl_GetPriority,
    IWineD3DVolumeTextureImpl_PreLoad,
    IWineD3DVolumeTextureImpl_UnLoad,
    IWineD3DVolumeTextureImpl_GetType,
    /* BaseTexture */
    IWineD3DVolumeTextureImpl_SetLOD,
    IWineD3DVolumeTextureImpl_GetLOD,
    IWineD3DVolumeTextureImpl_GetLevelCount,
    IWineD3DVolumeTextureImpl_SetAutoGenFilterType,
    IWineD3DVolumeTextureImpl_GetAutoGenFilterType,
    IWineD3DVolumeTextureImpl_GenerateMipSubLevels,
    /* not in d3d */
    IWineD3DVolumeTextureImpl_IsCondNP2,
    /* volume texture */
    IWineD3DVolumeTextureImpl_GetLevelDesc,
    IWineD3DVolumeTextureImpl_GetVolumeLevel,
    IWineD3DVolumeTextureImpl_Map,
    IWineD3DVolumeTextureImpl_Unmap,
    IWineD3DVolumeTextureImpl_AddDirtyBox
};

HRESULT volumetexture_init(IWineD3DVolumeTextureImpl *texture, UINT width, UINT height,
        UINT depth, UINT levels, IWineD3DDeviceImpl *device, DWORD usage, enum wined3d_format_id format_id,
        WINED3DPOOL pool, void *parent, const struct wined3d_parent_ops *parent_ops)
{
    const struct wined3d_gl_info *gl_info = &device->adapter->gl_info;
    const struct wined3d_format *format = wined3d_get_format(gl_info, format_id);
    UINT tmp_w, tmp_h, tmp_d;
    unsigned int i;
    HRESULT hr;

    /* TODO: It should only be possible to create textures for formats
     * that are reported as supported. */
    if (WINED3DFMT_UNKNOWN >= format_id)
    {
        WARN("(%p) : Texture cannot be created with a format of WINED3DFMT_UNKNOWN.\n", texture);
        return WINED3DERR_INVALIDCALL;
    }

    if (!gl_info->supported[EXT_TEXTURE3D])
    {
        WARN("(%p) : Texture cannot be created - no volume texture support.\n", texture);
        return WINED3DERR_INVALIDCALL;
    }

    /* Calculate levels for mip mapping. */
    if (usage & WINED3DUSAGE_AUTOGENMIPMAP)
    {
        if (!gl_info->supported[SGIS_GENERATE_MIPMAP])
        {
            WARN("No mipmap generation support, returning D3DERR_INVALIDCALL.\n");
            return WINED3DERR_INVALIDCALL;
        }

        if (levels > 1)
        {
            WARN("D3DUSAGE_AUTOGENMIPMAP is set, and level count > 1, returning D3DERR_INVALIDCALL.\n");
            return WINED3DERR_INVALIDCALL;
        }

        levels = 1;
    }
    else if (!levels)
    {
        levels = wined3d_log2i(max(max(width, height), depth)) + 1;
        TRACE("Calculated levels = %u.\n", levels);
    }

    texture->lpVtbl = &IWineD3DVolumeTexture_Vtbl;

    hr = basetexture_init((IWineD3DBaseTextureImpl *)texture, &volumetexture_ops,
            1, levels, WINED3DRTYPE_VOLUMETEXTURE, device, usage, format, pool,
            parent, parent_ops);
    if (FAILED(hr))
    {
        WARN("Failed to initialize basetexture, returning %#x.\n", hr);
        return hr;
    }

    /* Is NP2 support for volumes needed? */
    texture->baseTexture.pow2Matrix[0] = 1.0f;
    texture->baseTexture.pow2Matrix[5] = 1.0f;
    texture->baseTexture.pow2Matrix[10] = 1.0f;
    texture->baseTexture.pow2Matrix[15] = 1.0f;
    texture->baseTexture.target = GL_TEXTURE_3D;

    /* Generate all the surfaces. */
    tmp_w = width;
    tmp_h = height;
    tmp_d = depth;

    for (i = 0; i < texture->baseTexture.level_count; ++i)
    {
        IWineD3DVolume *volume;

        /* Create the volume. */
        hr = IWineD3DDeviceParent_CreateVolume(device->device_parent, parent,
                tmp_w, tmp_h, tmp_d, format_id, pool, usage, &volume);
        if (FAILED(hr))
        {
            ERR("Creating a volume for the volume texture failed, hr %#x.\n", hr);
            volumetexture_cleanup(texture);
            return hr;
        }

        /* Set its container to this texture. */
        volume_set_container((IWineD3DVolumeImpl *)volume, texture);
        texture->baseTexture.sub_resources[i] = (IWineD3DResourceImpl *)volume;

        /* Calculate the next mipmap level. */
        tmp_w = max(1, tmp_w >> 1);
        tmp_h = max(1, tmp_h >> 1);
        tmp_d = max(1, tmp_d >> 1);
    }

    return WINED3D_OK;
}
