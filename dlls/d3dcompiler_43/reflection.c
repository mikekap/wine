/*
 * Copyright 2009 Henri Verbeet for CodeWeavers
 * Copyright 2010 Rico Schüller
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
 *
 */

#include "config.h"
#include "wine/port.h"

#include "d3dcompiler_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3dcompiler);

static BOOL copy_name(const char *ptr, char **name)
{
    size_t name_len;

    if (!ptr) return TRUE;

    name_len = strlen(ptr) + 1;
    if (name_len == 1)
    {
        return TRUE;
    }

    *name = HeapAlloc(GetProcessHeap(), 0, name_len);
    if (!*name)
    {
        ERR("Failed to allocate name memory.\n");
        return FALSE;
    }

    memcpy(*name, ptr, name_len);

    return TRUE;
}

static void free_signature(struct d3dcompiler_shader_signature *sig)
{
    TRACE("Free signature %p\n", sig);

    HeapFree(GetProcessHeap(), 0, sig->elements);
    HeapFree(GetProcessHeap(), 0, sig->string_data);
}

static void reflection_cleanup(struct d3dcompiler_shader_reflection *ref)
{
    TRACE("Cleanup %p\n", ref);

    if (ref->isgn)
    {
        free_signature(ref->isgn);
        HeapFree(GetProcessHeap(), 0, ref->isgn);
    }

    if (ref->osgn)
    {
        free_signature(ref->osgn);
        HeapFree(GetProcessHeap(), 0, ref->osgn);
    }

    if (ref->pcsg)
    {
        free_signature(ref->pcsg);
        HeapFree(GetProcessHeap(), 0, ref->pcsg);
    }

    HeapFree(GetProcessHeap(), 0, ref->creator);
}

static inline struct d3dcompiler_shader_reflection *impl_from_ID3D11ShaderReflection(ID3D11ShaderReflection *iface)
{
    return CONTAINING_RECORD(iface, struct d3dcompiler_shader_reflection, ID3D11ShaderReflection_iface);
}

/* IUnknown methods */

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_QueryInterface(ID3D11ShaderReflection *iface, REFIID riid, void **object)
{
    TRACE("iface %p, riid %s, object %p\n", iface, debugstr_guid(riid), object);

    if (IsEqualGUID(riid, &IID_ID3D11ShaderReflection)
            || IsEqualGUID(riid, &IID_IUnknown))
    {
        IUnknown_AddRef(iface);
        *object = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE\n", debugstr_guid(riid));

    *object = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE d3dcompiler_shader_reflection_AddRef(ID3D11ShaderReflection *iface)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);
    ULONG refcount = InterlockedIncrement(&This->refcount);

    TRACE("%p increasing refcount to %u\n", This, refcount);

    return refcount;
}

static ULONG STDMETHODCALLTYPE d3dcompiler_shader_reflection_Release(ID3D11ShaderReflection *iface)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);
    ULONG refcount = InterlockedDecrement(&This->refcount);

    TRACE("%p decreasing refcount to %u\n", This, refcount);

    if (!refcount)
    {
        reflection_cleanup(This);
        HeapFree(GetProcessHeap(), 0, This);
    }

    return refcount;
}

/* ID3D11ShaderReflection methods */

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetDesc(ID3D11ShaderReflection *iface, D3D11_SHADER_DESC *desc)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    FIXME("iface %p, desc %p partial stub!\n", iface, desc);

    if (!desc)
    {
        WARN("Invalid argument specified\n");
        return E_FAIL;
    }

    desc->Version = This->version;
    desc->Creator = This->creator;
    desc->Flags = This->flags;
    desc->ConstantBuffers = This->constant_buffer_count;
    desc->BoundResources = This->bound_resource_count;
    desc->InputParameters = This->isgn ? This->isgn->element_count : 0;
    desc->OutputParameters = This->osgn ? This->osgn->element_count : 0;
    desc->InstructionCount = This->instruction_count;
    desc->TempRegisterCount = This->temp_register_count;
    desc->TempArrayCount = This->temp_array_count;
    desc->DefCount = 0;
    desc->DclCount = This->dcl_count;
    desc->TextureNormalInstructions = This->texture_normal_instructions;
    desc->TextureLoadInstructions = This->texture_load_instructions;
    desc->TextureCompInstructions = This->texture_comp_instructions;
    desc->TextureBiasInstructions = This->texture_bias_instructions;
    desc->TextureGradientInstructions = This->texture_gradient_instructions;
    desc->FloatInstructionCount = This->float_instruction_count;
    desc->IntInstructionCount = This->int_instruction_count;
    desc->UintInstructionCount = This->uint_instruction_count;
    desc->StaticFlowControlCount = This->static_flow_control_count;
    desc->DynamicFlowControlCount = This->dynamic_flow_control_count;
    desc->MacroInstructionCount = 0;
    desc->ArrayInstructionCount = This->array_instruction_count;
    desc->CutInstructionCount = This->cut_instruction_count;
    desc->EmitInstructionCount = This->emit_instruction_count;
    desc->GSOutputTopology = This->gs_output_topology;
    desc->GSMaxOutputVertexCount = This->gs_max_output_vertex_count;
    desc->InputPrimitive = This->input_primitive;
    desc->PatchConstantParameters = This->pcsg ? This->pcsg->element_count : 0;
    desc->cGSInstanceCount = 0;
    desc->cControlPoints = This->c_control_points;
    desc->HSOutputPrimitive = This->hs_output_primitive;
    desc->HSPartitioning = This->hs_prtitioning;
    desc->TessellatorDomain = This->tessellator_domain;
    desc->cBarrierInstructions = 0;
    desc->cInterlockedInstructions = 0;
    desc->cTextureStoreInstructions = 0;

    return S_OK;
}

static struct ID3D11ShaderReflectionConstantBuffer * STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetConstantBufferByIndex(
        ID3D11ShaderReflection *iface, UINT index)
{
    FIXME("iface %p, index %u stub!\n", iface, index);

    return NULL;
}

static struct ID3D11ShaderReflectionConstantBuffer * STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetConstantBufferByName(
        ID3D11ShaderReflection *iface, LPCSTR name)
{
    FIXME("iface %p, name \"%s\" stub!\n", iface, name);

    return NULL;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetResourceBindingDesc(
        ID3D11ShaderReflection *iface, UINT index, D3D11_SHADER_INPUT_BIND_DESC *desc)
{
    FIXME("iface %p, index %u, desc %p stub!\n", iface, index, desc);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetInputParameterDesc(
        ID3D11ShaderReflection *iface, UINT index, D3D11_SIGNATURE_PARAMETER_DESC *desc)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    TRACE("iface %p, index %u, desc %p\n", iface, index, desc);

    if (!desc || !This->isgn || index >= This->isgn->element_count)
    {
        WARN("Invalid argument specified\n");
        return E_INVALIDARG;
    }

    *desc = This->isgn->elements[index];

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetOutputParameterDesc(
        ID3D11ShaderReflection *iface, UINT index, D3D11_SIGNATURE_PARAMETER_DESC *desc)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    TRACE("iface %p, index %u, desc %p\n", iface, index, desc);

    if (!desc || !This->osgn || index >= This->osgn->element_count)
    {
        WARN("Invalid argument specified\n");
        return E_INVALIDARG;
    }

    *desc = This->osgn->elements[index];

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetPatchConstantParameterDesc(
        ID3D11ShaderReflection *iface, UINT index, D3D11_SIGNATURE_PARAMETER_DESC *desc)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    TRACE("iface %p, index %u, desc %p\n", iface, index, desc);

    if (!desc || !This->pcsg || index >= This->pcsg->element_count)
    {
        WARN("Invalid argument specified\n");
        return E_INVALIDARG;
    }

    *desc = This->pcsg->elements[index];

    return S_OK;
}

static struct ID3D11ShaderReflectionVariable * STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetVariableByName(
        ID3D11ShaderReflection *iface, LPCSTR name)
{
    FIXME("iface %p, name %s stub!\n", iface, name);

    return NULL;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetResourceBindingDescByName(
        ID3D11ShaderReflection *iface, LPCSTR name, D3D11_SHADER_INPUT_BIND_DESC *desc)
{
    FIXME("iface %p, name %s, desc %p stub!\n", iface, name, desc);

    return E_NOTIMPL;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetMovInstructionCount(
        ID3D11ShaderReflection *iface)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    TRACE("iface %p\n", iface);

    return This->mov_instruction_count;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetMovcInstructionCount(
        ID3D11ShaderReflection *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetConversionInstructionCount(
        ID3D11ShaderReflection *iface)
{
    struct d3dcompiler_shader_reflection *This = impl_from_ID3D11ShaderReflection(iface);

    TRACE("iface %p\n", iface);

    return This->conversion_instruction_count;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetBitwiseInstructionCount(
        ID3D11ShaderReflection *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static D3D_PRIMITIVE STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetGSInputPrimitive(
        ID3D11ShaderReflection *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static BOOL STDMETHODCALLTYPE d3dcompiler_shader_reflection_IsSampleFrequencyShader(
        ID3D11ShaderReflection *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetNumInterfaceSlots(
        ID3D11ShaderReflection *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static HRESULT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetMinFeatureLevel(
        ID3D11ShaderReflection *iface, D3D_FEATURE_LEVEL *level)
{
    FIXME("iface %p, level %p stub!\n", iface, level);

    return E_NOTIMPL;
}

static UINT STDMETHODCALLTYPE d3dcompiler_shader_reflection_GetThreadGroupSize(
        ID3D11ShaderReflection *iface, UINT *sizex, UINT *sizey, UINT *sizez)
{
    FIXME("iface %p, sizex %p, sizey %p, sizez %p stub!\n", iface, sizex, sizey, sizez);

    return 0;
}

const struct ID3D11ShaderReflectionVtbl d3dcompiler_shader_reflection_vtbl =
{
    /* IUnknown methods */
    d3dcompiler_shader_reflection_QueryInterface,
    d3dcompiler_shader_reflection_AddRef,
    d3dcompiler_shader_reflection_Release,
    /* ID3D11ShaderReflection methods */
    d3dcompiler_shader_reflection_GetDesc,
    d3dcompiler_shader_reflection_GetConstantBufferByIndex,
    d3dcompiler_shader_reflection_GetConstantBufferByName,
    d3dcompiler_shader_reflection_GetResourceBindingDesc,
    d3dcompiler_shader_reflection_GetInputParameterDesc,
    d3dcompiler_shader_reflection_GetOutputParameterDesc,
    d3dcompiler_shader_reflection_GetPatchConstantParameterDesc,
    d3dcompiler_shader_reflection_GetVariableByName,
    d3dcompiler_shader_reflection_GetResourceBindingDescByName,
    d3dcompiler_shader_reflection_GetMovInstructionCount,
    d3dcompiler_shader_reflection_GetMovcInstructionCount,
    d3dcompiler_shader_reflection_GetConversionInstructionCount,
    d3dcompiler_shader_reflection_GetBitwiseInstructionCount,
    d3dcompiler_shader_reflection_GetGSInputPrimitive,
    d3dcompiler_shader_reflection_IsSampleFrequencyShader,
    d3dcompiler_shader_reflection_GetNumInterfaceSlots,
    d3dcompiler_shader_reflection_GetMinFeatureLevel,
    d3dcompiler_shader_reflection_GetThreadGroupSize,
};

static HRESULT d3dcompiler_parse_stat(struct d3dcompiler_shader_reflection *r, const char *data, DWORD data_size)
{
    const char *ptr = data;
    DWORD size = data_size >> 2;

    TRACE("Size %u\n", size);

    read_dword(&ptr, &r->instruction_count);
    TRACE("InstructionCount: %u\n", r->instruction_count);

    read_dword(&ptr, &r->temp_register_count);
    TRACE("TempRegisterCount: %u\n", r->temp_register_count);

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->dcl_count);
    TRACE("DclCount: %u\n", r->dcl_count);

    read_dword(&ptr, &r->float_instruction_count);
    TRACE("FloatInstructionCount: %u\n", r->float_instruction_count);

    read_dword(&ptr, &r->int_instruction_count);
    TRACE("IntInstructionCount: %u\n", r->int_instruction_count);

    read_dword(&ptr, &r->uint_instruction_count);
    TRACE("UintInstructionCount: %u\n", r->uint_instruction_count);

    read_dword(&ptr, &r->static_flow_control_count);
    TRACE("StaticFlowControlCount: %u\n", r->static_flow_control_count);

    read_dword(&ptr, &r->dynamic_flow_control_count);
    TRACE("DynamicFlowControlCount: %u\n", r->dynamic_flow_control_count);

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->temp_array_count);
    TRACE("TempArrayCount: %u\n", r->temp_array_count);

    read_dword(&ptr, &r->array_instruction_count);
    TRACE("ArrayInstructionCount: %u\n", r->array_instruction_count);

    read_dword(&ptr, &r->cut_instruction_count);
    TRACE("CutInstructionCount: %u\n", r->cut_instruction_count);

    read_dword(&ptr, &r->emit_instruction_count);
    TRACE("EmitInstructionCount: %u\n", r->emit_instruction_count);

    read_dword(&ptr, &r->texture_normal_instructions);
    TRACE("TextureNormalInstructions: %u\n", r->texture_normal_instructions);

    read_dword(&ptr, &r->texture_load_instructions);
    TRACE("TextureLoadInstructions: %u\n", r->texture_load_instructions);

    read_dword(&ptr, &r->texture_comp_instructions);
    TRACE("TextureCompInstructions: %u\n", r->texture_comp_instructions);

    read_dword(&ptr, &r->texture_bias_instructions);
    TRACE("TextureBiasInstructions: %u\n", r->texture_bias_instructions);

    read_dword(&ptr, &r->texture_gradient_instructions);
    TRACE("TextureGradientInstructions: %u\n", r->texture_gradient_instructions);

    read_dword(&ptr, &r->mov_instruction_count);
    TRACE("MovInstructionCount: %u\n", r->mov_instruction_count);

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->conversion_instruction_count);
    TRACE("ConversionInstructionCount: %u\n", r->conversion_instruction_count);

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->input_primitive);
    TRACE("InputPrimitive: %x\n", r->input_primitive);

    read_dword(&ptr, &r->gs_output_topology);
    TRACE("GSOutputTopology: %x\n", r->gs_output_topology);

    read_dword(&ptr, &r->gs_max_output_vertex_count);
    TRACE("GSMaxOutputVertexCount: %u\n", r->gs_max_output_vertex_count);

    skip_dword_unknown(&ptr, 3);

    /* dx10 stat size */
    if (size == 29) return S_OK;

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->c_control_points);
    TRACE("cControlPoints: %u\n", r->c_control_points);

    read_dword(&ptr, &r->hs_output_primitive);
    TRACE("HSOutputPrimitive: %x\n", r->hs_output_primitive);

    read_dword(&ptr, &r->hs_prtitioning);
    TRACE("HSPartitioning: %x\n", r->hs_prtitioning);

    read_dword(&ptr, &r->tessellator_domain);
    TRACE("TessellatorDomain: %x\n", r->tessellator_domain);

    skip_dword_unknown(&ptr, 3);

    /* dx11 stat size */
    if (size == 37) return S_OK;

    FIXME("Unhandled size %u\n", size);

    return E_FAIL;
}

static HRESULT d3dcompiler_parse_rdef(struct d3dcompiler_shader_reflection *r, const char *data, DWORD data_size)
{
    const char *ptr = data;
    DWORD size = data_size >> 2;
    DWORD offset;

    TRACE("Size %u\n", size);

    read_dword(&ptr, &r->constant_buffer_count);
    TRACE("Constant buffer count: %u\n", r->constant_buffer_count);

    read_dword(&ptr, &offset);
    TRACE("Constant buffer offset: %x\n", offset);

    read_dword(&ptr, &r->bound_resource_count);
    TRACE("Bound resource count: %u\n", r->bound_resource_count);

    read_dword(&ptr, &offset);
    TRACE("Bound resource offset: %x\n", offset);

    skip_dword_unknown(&ptr, 1);

    read_dword(&ptr, &r->flags);
    TRACE("Flags: %u\n", r->flags);

    read_dword(&ptr, &offset);
    TRACE("Creator at offset %#x.\n", offset);

    if (!copy_name(data + offset, &r->creator))
    {
        ERR("Failed to copy name.\n");
        return E_OUTOFMEMORY;
    }
    TRACE("Creator: %s.\n", debugstr_a(r->creator));

    /* todo: Parse D3D11_SHADER_INPUT_BIND_DESC Structure */

    /* todo: Parse Constant buffers */

    return S_OK;
}

HRESULT d3dcompiler_parse_signature(struct d3dcompiler_shader_signature *s, const char *data, DWORD data_size)
{
    D3D11_SIGNATURE_PARAMETER_DESC *d;
    unsigned int string_data_offset;
    unsigned int string_data_size;
    const char *ptr = data;
    char *string_data;
    unsigned int i;
    DWORD count;

    read_dword(&ptr, &count);
    TRACE("%u elements\n", count);

    skip_dword_unknown(&ptr, 1);

    d = HeapAlloc(GetProcessHeap(), 0, count * sizeof(*d));
    if (!d)
    {
        ERR("Failed to allocate signature memory.\n");
        return E_OUTOFMEMORY;
    }

    /* 2 DWORDs for the header, 6 for each element. */
    string_data_offset = 2 * sizeof(DWORD) + count * 6 * sizeof(DWORD);
    string_data_size = data_size - string_data_offset;
    string_data = HeapAlloc(GetProcessHeap(), 0, string_data_size);
    if (!string_data)
    {
        ERR("Failed to allocate string data memory.\n");
        HeapFree(GetProcessHeap(), 0, d);
        return E_OUTOFMEMORY;
    }
    memcpy(string_data, data + string_data_offset, string_data_size);

    for (i = 0; i < count; ++i)
    {
        UINT name_offset;
        DWORD mask;

        /* todo: Parse stream in shaderblobs v5 (dx11) */
        d[i].Stream = 0;

        read_dword(&ptr, &name_offset);
        d[i].SemanticName = string_data + (name_offset - string_data_offset);
        read_dword(&ptr, &d[i].SemanticIndex);
        read_dword(&ptr, &d[i].SystemValueType);
        read_dword(&ptr, &d[i].ComponentType);
        read_dword(&ptr, &d[i].Register);
        read_dword(&ptr, &mask);
        d[i].ReadWriteMask = (mask >> 8) & 0xff;
        d[i].Mask = mask & 0xff;

        TRACE("semantic: %s, semantic idx: %u, sysval_semantic %#x, "
                "type %u, register idx: %u, use_mask %#x, input_mask %#x, stream %u\n",
                debugstr_a(d[i].SemanticName), d[i].SemanticIndex, d[i].SystemValueType,
                d[i].ComponentType, d[i].Register, d[i].Mask, d[i].ReadWriteMask, d[i].Stream);
    }

    s->elements = d;
    s->element_count = count;
    s->string_data = string_data;

    return S_OK;
}

static HRESULT d3dcompiler_parse_shdr(struct d3dcompiler_shader_reflection *r, const char *data, DWORD data_size)
{
    const char *ptr = data;

    read_dword(&ptr, &r->version);
    TRACE("Shader version: %u\n", r->version);

    /* todo: Check if anything else is needed from the shdr or shex blob. */

    return S_OK;
}

HRESULT d3dcompiler_shader_reflection_init(struct d3dcompiler_shader_reflection *reflection,
        const void *data, SIZE_T data_size)
{
    struct dxbc src_dxbc;
    HRESULT hr;
    unsigned int i;

    reflection->ID3D11ShaderReflection_iface.lpVtbl = &d3dcompiler_shader_reflection_vtbl;
    reflection->refcount = 1;

    hr = dxbc_parse(data, data_size, &src_dxbc);
    if (FAILED(hr))
    {
        WARN("Failed to parse reflection\n");
        return hr;
    }

    for (i = 0; i < src_dxbc.count; ++i)
    {
        struct dxbc_section *section = &src_dxbc.sections[i];

        switch (section->tag)
        {
            case TAG_STAT:
                hr = d3dcompiler_parse_stat(reflection, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse section STAT.\n");
                    goto err_out;
                }
                break;

            case TAG_SHEX:
            case TAG_SHDR:
                hr = d3dcompiler_parse_shdr(reflection, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse SHDR section.\n");
                    goto err_out;
                }
                break;

            case TAG_RDEF:
                hr = d3dcompiler_parse_rdef(reflection, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse RDEF section.\n");
                    goto err_out;
                }
                break;

            case TAG_ISGN:
                reflection->isgn = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*reflection->isgn));
                if (!reflection->isgn)
                {
                    ERR("Failed to allocate ISGN memory.\n");
                    hr = E_OUTOFMEMORY;
                    goto err_out;
                }

                hr = d3dcompiler_parse_signature(reflection->isgn, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse section ISGN.\n");
                    goto err_out;
                }
                break;

            case TAG_OSGN:
                reflection->osgn = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*reflection->osgn));
                if (!reflection->osgn)
                {
                    ERR("Failed to allocate OSGN memory.\n");
                    hr = E_OUTOFMEMORY;
                    goto err_out;
                }

                hr = d3dcompiler_parse_signature(reflection->osgn, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse section OSGN.\n");
                    goto err_out;
                }
                break;

            case TAG_PCSG:
                reflection->pcsg = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*reflection->pcsg));
                if (!reflection->pcsg)
                {
                    ERR("Failed to allocate PCSG memory.\n");
                    hr = E_OUTOFMEMORY;
                    goto err_out;
                }

                hr = d3dcompiler_parse_signature(reflection->pcsg, section->data, section->data_size);
                if (FAILED(hr))
                {
                    WARN("Failed to parse section PCSG.\n");
                    goto err_out;
                }
                break;

            default:
                FIXME("Unhandled section %s!\n", debugstr_an((const char *)&section->tag, 4));
                break;
        }
    }

    dxbc_destroy(&src_dxbc);

    return hr;

err_out:
    reflection_cleanup(reflection);
    dxbc_destroy(&src_dxbc);

    return hr;
}
