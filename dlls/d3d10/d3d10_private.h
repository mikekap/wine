/*
 * Copyright 2008-2009 Henri Verbeet for CodeWeavers
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

#ifndef __WINE_D3D10_PRIVATE_H
#define __WINE_D3D10_PRIVATE_H

#include "wine/debug.h"
#include "wine/rbtree.h"

#define COBJMACROS
#include "winbase.h"
#include "winuser.h"
#include "objbase.h"

#include "d3d10.h"
#include "d3dcompiler.h"

/*
 * This doesn't belong here, but for some functions it is possible to return that value,
 * see http://msdn.microsoft.com/en-us/library/bb205278%28v=VS.85%29.aspx
 * The original definition is in D3DX10core.h.
 */
#define D3DERR_INVALIDCALL 0x8876086c

/* TRACE helper functions */
const char *debug_d3d10_driver_type(D3D10_DRIVER_TYPE driver_type) DECLSPEC_HIDDEN;
const char *debug_d3d10_shader_variable_class(D3D10_SHADER_VARIABLE_CLASS c) DECLSPEC_HIDDEN;
const char *debug_d3d10_shader_variable_type(D3D10_SHADER_VARIABLE_TYPE t) DECLSPEC_HIDDEN;

void *d3d10_rb_alloc(size_t size) DECLSPEC_HIDDEN;
void *d3d10_rb_realloc(void *ptr, size_t size) DECLSPEC_HIDDEN;
void d3d10_rb_free(void *ptr) DECLSPEC_HIDDEN;

enum d3d10_effect_object_type
{
    D3D10_EOT_VERTEXSHADER = 6,
    D3D10_EOT_PIXELSHADER = 7,
    D3D10_EOT_GEOMETRYSHADER = 8,
};

enum d3d10_effect_object_operation
{
    D3D10_EOO_VALUE = 1,
    D3D10_EOO_PARSED_OBJECT = 2,
    D3D10_EOO_PARSED_OBJECT_INDEX = 3,
    D3D10_EOO_ANONYMOUS_SHADER = 7,
};

struct d3d10_effect_object
{
    struct d3d10_effect_pass *pass;
    enum d3d10_effect_object_type type;
    DWORD idx_offset;
    DWORD index;
    void *data;
};

struct d3d10_effect_shader_signature
{
    char *signature;
    UINT signature_size;
    UINT element_count;
    D3D10_SIGNATURE_PARAMETER_DESC *elements;
};

struct d3d10_effect_shader_variable
{
    struct d3d10_effect_shader_signature input_signature;
    struct d3d10_effect_shader_signature output_signature;
    union
    {
        ID3D10VertexShader *vs;
        ID3D10PixelShader *ps;
        ID3D10GeometryShader *gs;
    } shader;
};

/* ID3D10EffectType */
struct d3d10_effect_type
{
    const struct ID3D10EffectTypeVtbl *vtbl;

    char *name;
    D3D10_SHADER_VARIABLE_TYPE basetype;
    D3D10_SHADER_VARIABLE_CLASS type_class;

    DWORD id;
    struct wine_rb_entry entry;
    struct d3d10_effect *effect;

    DWORD element_count;
    DWORD size_unpacked;
    DWORD stride;
    DWORD size_packed;
    DWORD member_count;
    DWORD column_count;
    DWORD row_count;
    struct d3d10_effect_type *elementtype;
    struct d3d10_effect_type_member *members;
};

struct d3d10_effect_type_member
{
    char *name;
    char *semantic;
    DWORD buffer_offset;
    struct d3d10_effect_type *type;
};

/* ID3D10EffectVariable */
struct d3d10_effect_variable
{
    const struct ID3D10EffectVariableVtbl *vtbl;

    struct d3d10_effect_variable *buffer;
    struct d3d10_effect_type *type;

    void *data;
    char *name;
    char *semantic;
    DWORD buffer_offset;
    DWORD annotation_count;
    DWORD flag;
    DWORD data_size;
    struct d3d10_effect *effect;
    struct d3d10_effect_variable *elements;
    struct d3d10_effect_variable *members;
    struct d3d10_effect_variable *annotations;
};

/* ID3D10EffectPass */
struct d3d10_effect_pass
{
    const struct ID3D10EffectPassVtbl *vtbl;

    struct d3d10_effect_technique *technique;
    char *name;
    DWORD start;
    DWORD object_count;
    DWORD annotation_count;
    struct d3d10_effect_object *objects;
    struct d3d10_effect_variable *annotations;
};

/* ID3D10EffectTechnique */
struct d3d10_effect_technique
{
    const struct ID3D10EffectTechniqueVtbl *vtbl;

    struct d3d10_effect *effect;
    char *name;
    DWORD pass_count;
    DWORD annotation_count;
    struct d3d10_effect_pass *passes;
    struct d3d10_effect_variable *annotations;
};

struct d3d10_effect_anonymous_shader
{
    struct d3d10_effect_variable shader;
    struct d3d10_effect_type type;
};

/* ID3D10Effect */
extern const struct ID3D10EffectVtbl d3d10_effect_vtbl DECLSPEC_HIDDEN;
struct d3d10_effect
{
    const struct ID3D10EffectVtbl *vtbl;
    LONG refcount;

    ID3D10Device *device;
    DWORD version;
    DWORD local_buffer_count;
    DWORD variable_count;
    DWORD local_variable_count;
    DWORD sharedbuffers_count;
    DWORD sharedobjects_count;
    DWORD technique_count;
    DWORD index_offset;
    DWORD texture_count;
    DWORD dephstencilstate_count;
    DWORD blendstate_count;
    DWORD rasterizerstate_count;
    DWORD samplerstate_count;
    DWORD rendertargetview_count;
    DWORD depthstencilview_count;
    DWORD used_shader_count;
    DWORD anonymous_shader_count;

    DWORD used_shader_current;
    DWORD anonymous_shader_current;

    struct wine_rb_tree types;
    struct d3d10_effect_variable *local_buffers;
    struct d3d10_effect_variable *local_variables;
    struct d3d10_effect_anonymous_shader *anonymous_shaders;
    struct d3d10_effect_variable **used_shaders;
    struct d3d10_effect_technique *techniques;
};

/* ID3D10ShaderReflection */
extern const struct ID3D10ShaderReflectionVtbl d3d10_shader_reflection_vtbl DECLSPEC_HIDDEN;
struct d3d10_shader_reflection
{
    const struct ID3D10ShaderReflectionVtbl *vtbl;
    LONG refcount;
};

HRESULT d3d10_effect_parse(struct d3d10_effect *This, const void *data, SIZE_T data_size) DECLSPEC_HIDDEN;

/* D3D10Core */
HRESULT WINAPI D3D10CoreCreateDevice(IDXGIFactory *factory, IDXGIAdapter *adapter,
        UINT flags, void *unknown0, ID3D10Device **device);

#define MAKE_TAG(ch0, ch1, ch2, ch3) \
    ((DWORD)(ch0) | ((DWORD)(ch1) << 8) | \
    ((DWORD)(ch2) << 16) | ((DWORD)(ch3) << 24 ))
#define TAG_DXBC MAKE_TAG('D', 'X', 'B', 'C')
#define TAG_FX10 MAKE_TAG('F', 'X', '1', '0')
#define TAG_ISGN MAKE_TAG('I', 'S', 'G', 'N')
#define TAG_OSGN MAKE_TAG('O', 'S', 'G', 'N')
#define TAG_SHDR MAKE_TAG('S', 'H', 'D', 'R')

HRESULT parse_dxbc(const char *data, SIZE_T data_size,
        HRESULT (*chunk_handler)(const char *data, DWORD data_size, DWORD tag, void *ctx), void *ctx) DECLSPEC_HIDDEN;

static inline void read_dword(const char **ptr, DWORD *d)
{
    memcpy(d, *ptr, sizeof(*d));
    *ptr += sizeof(*d);
}

static inline void write_dword(char **ptr, DWORD d)
{
    memcpy(*ptr, &d, sizeof(d));
    *ptr += sizeof(d);
}

void skip_dword_unknown(const char **ptr, unsigned int count) DECLSPEC_HIDDEN;
void write_dword_unknown(char **ptr, DWORD d) DECLSPEC_HIDDEN;

#endif /* __WINE_D3D10_PRIVATE_H */
