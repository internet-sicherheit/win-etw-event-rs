use core::panic;

use crate::helper::make_function_name;
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::{format_ident, quote};
use win_etw_manifest::template::*;

/// Generate a function for every passed template
///
/// Functions belong to a provider struct.
/// Every generated function parses the payload defined by the template.
pub(crate) fn generate_templates(provider: Ident, templates: &[Template]) -> TokenStream {
    let mut template_functions = Vec::new();
    for t in templates {
        let fn_name = template_fn_name(t);
        let (parse_arg1, names): (Vec<Ident>, Vec<_>) = t
            .data
            .iter()
            .map(|d| (in_type_ident(d), Literal::string(&d.name)))
            .unzip();
        let binary_sizes: Vec<_> = t
            .data
            .iter()
            .map(|d| match &d.length {
                Some(l) => quote! {
                    {
                        let x: &crate::modern_event::types::WinInTypeItem = map.get(#l).ok_or(::std::io::Error::other("length to parse binary data not found"))?;
                        match x {
                            crate::modern_event::types::WinInTypeItem::Int8(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::UInt8(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::Int16(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::UInt16(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::Int32(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::UInt32(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::Int64(x) => ::core::option::Option::Some(*x as u16),
                            crate::modern_event::types::WinInTypeItem::UInt64(x) => ::core::option::Option::Some(*x as u16),
                            _ => ::core::option::Option::None
                        }
                    }
                },
                None => quote!(None),
            })
            .collect();
        let ts = quote! {
            fn #fn_name(&mut self) -> ::core::result::Result<(), crate::modern_event::ModernEventError> {
                use ::core::ops::DerefMut;
                let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> = ::std::collections::HashMap::new();

                #(
                    let size: ::core::option::Option<u16> = #binary_sizes;
                    map.insert(#names, self.modern_event.read_payload_item(crate::modern_event::WinInType::#parse_arg1, size)?);
                )*
                self.payload = Some(map);
                Ok(())
            }
        };
        template_functions.push(ts);
    }
    quote! {
        impl #provider {
            #(#template_functions)*
        }
    }
}

fn template_fn_name(t: &Template) -> Ident {
    let mut name = t.tid.clone();

    if !name.is_ascii() {
        panic!(
            "Non ASCII template id \"{}\" found, which is not supported!",
            name
        );
    }
    make_function_name(&mut name);

    format_ident!("parse_payload_{name}")
}

fn in_type_ident(d: &DataType) -> Ident {
    match d.in_type {
        WinInType::Int8 => Ident::new("Int8", Span::call_site()),
        WinInType::UInt8 => Ident::new("UInt8", Span::call_site()),
        WinInType::Int16 => Ident::new("Int16", Span::call_site()),
        WinInType::UInt16 => Ident::new("UInt16", Span::call_site()),
        WinInType::Int32 => Ident::new("Int32", Span::call_site()),
        WinInType::UInt32 => Ident::new("UInt32", Span::call_site()),
        WinInType::Int64 => Ident::new("Int64", Span::call_site()),
        WinInType::UInt64 => Ident::new("UInt64", Span::call_site()),
        WinInType::Float => Ident::new("Float", Span::call_site()),
        WinInType::Double => Ident::new("Double", Span::call_site()),
        WinInType::Boolean => Ident::new("Boolean", Span::call_site()),
        WinInType::AnsiString => Ident::new("AnsiString", Span::call_site()),
        WinInType::UnicodeString => Ident::new("UnicodeString", Span::call_site()),
        WinInType::Binary => Ident::new("Binary", Span::call_site()),
        WinInType::Pointer => Ident::new("Pointer", Span::call_site()),
        WinInType::SizeT => Ident::new("SizeT", Span::call_site()),
        WinInType::Guid => Ident::new("Guid", Span::call_site()),
        WinInType::Sid => Ident::new("Sid", Span::call_site()),
        WinInType::Filetime => Ident::new("Filetime", Span::call_site()),
        WinInType::Systemtime => Ident::new("Systemtime", Span::call_site()),
        _ => panic!("Unsupported WinInType found ({:?})", d.in_type),
    }
}
