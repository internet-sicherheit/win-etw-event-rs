mod helper;
mod template;

use std::{
    fs::{read_dir, File},
    path::Path,
};

use etw_manifest::{parse, Event, Provider};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

#[proc_macro]
pub fn include_manifests(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = match input.into_iter().next().unwrap() {
        proc_macro::TokenTree::Literal(x) => x.to_string(),
        _ => panic!("Input must be path literal"),
    };
    let str_path = input.trim_matches('"');
    let path = Path::new(&str_path);

    // read all files from path
    let files: Vec<_> = read_dir(path)
        .unwrap()
        .filter_map(|x| x.ok())
        .filter(|x| x.file_type().is_ok_and(|x| x.is_file()))
        .map(|x| x.path())
        .collect();

    let xml_files: Vec<_> = files
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ex| ex == "xml"))
        .collect();

    let mut providers = Vec::new();

    for path in xml_files {
        if let Ok(mut f) = File::open(&path) {
            match parse(&mut f) {
                Ok(provider) => {
                    providers.push(provider);
                }
                Err(e) => {
                    eprintln!("Parsing of {path:?} failed: {e}");
                    // parsing failed
                    // TODO use experimental diagnostic api to issue a warning
                }
            }
        } else {
            eprintln!("Failed to open {path:?}");
            // opening of file failed
            // TODO use experimental diagnostic api to issue a warning
        }
    }
    create_quote(&providers).into()
}

fn create_quote(providers: &[Provider]) -> proc_macro2::TokenStream {
    let provider_structs = quote_provider_structs(providers);

    quote! {
        /// Event Providers
        ///
        /// Event providers which are generated from their instrumentation manifest.
        pub mod provider {
            use super::*;
            #provider_structs
        }
    }
}

fn quote_provider_structs(providers: &[Provider]) -> proc_macro2::TokenStream {
    let mut quotes: Vec<proc_macro2::TokenStream> = Vec::new();
    for p in providers {
        quotes.push(quote_provider_struct(p));
    }

    let (guid_idents, struct_idents): (Vec<_>, Vec<_>) = providers
        .iter()
        .map(|x| {
            (
                guid_constant_name(x),
                proc_macro2::Ident::new(x.symbol.as_str(), proc_macro2::Span::call_site()),
            )
        })
        .unzip();

    quote! {
        impl ModernEvent {
            /// Try to wrap this opaque event in a concise event
            ///
            /// Returns None if no implementation for the provided event exists.
            pub fn into_contained_event(self) -> Option<Box<dyn Event>> {
                match self.header.provider_id {
                    #(#struct_idents::#guid_idents => Some(Box::new(#struct_idents::from(self))),)*
                    _ => None,
                }
            }
        }
        #(#quotes)*
    }
}

fn quote_provider_struct(p: &Provider) -> TokenStream {
    let symbol = proc_macro2::Ident::new(p.symbol.as_str(), proc_macro2::Span::call_site());

    let guid = p.guid.to_string();
    let guid_const_name = guid_constant_name(p);

    let name = p.name.as_str();

    let (event_ids, event_tasks): (Vec<_>, Vec<_>) = p
        .events
        .iter()
        .map(|x| {
            (
                proc_macro2::Literal::u16_unsuffixed(x.value),
                x.task.as_str(),
            )
        })
        .unzip();

    let (unique_ids, event_symbol): (Vec<_>, Vec<_>) = p
        .events
        .iter()
        .map(|e| (event_ident_tuple(e), e.symbol.as_str()))
        .unzip();

    let (event_to_template, template_fn): (Vec<_>, Vec<_>) = p
        .events
        .iter()
        .filter(|e| event_template_fn_ident(e).is_some())
        .map(|e| (event_ident_tuple(e), event_template_fn_ident(e).unwrap()))
        .unzip();

    let templates = template::generate_templates(symbol.clone(), &p.templates);
    quote! {
        #[derive(Debug)]
        pub struct #symbol {
            modern_event: crate::modern_event::ModernEvent,
            payload: ::core::option::Option<::std::collections::HashMap<&'static str, crate::modern_event::types::WinInTypeItem>>,
        }
        impl #symbol {
            pub const #guid_const_name: Uuid = uuid!(#guid);
            /// Wraps a [ModernEvent] into this concise event
            ///
            /// _Warning:_ No checks are performed if the [ModernEvent] is of this event type
            fn from(value: crate::modern_event::ModernEvent) -> Self {
                Self { modern_event: value, payload: None }
            }
        }
        impl ::core::ops::Deref for #symbol {
            type Target = crate::modern_event::ModernEvent;
            fn deref(&self) -> &Self::Target {
                &self.modern_event
            }
        }
        impl ::core::ops::DerefMut for #symbol {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.modern_event
            }
        }
        impl ::core::convert::TryFrom<crate::modern_event::ModernEvent> for #symbol {
            type Error = &'static str;
            fn try_from(value: crate::modern_event::ModernEvent) -> ::core::result::Result<Self, Self::Error> {
                if matches!(value.header.provider_id, Self::#guid_const_name) {
                    Ok(Self { modern_event: value, payload: None })
                } else {
                    Err("GUID of event doesn't match")
                }

            }
        }
        impl Event for #symbol {
            fn get_provider_name(&self) -> &str {
                #name
            }
            fn get_event_task_name(&self) -> Option<&str> {
                match self.header.event_descriptor.id {
                    #(#event_ids => Some(#event_tasks),)*
                    _ => None,
                }
            }
            fn get_event_symbol(&self) -> Option<&str> {
                let ed = &self.header.event_descriptor;
                match (ed.id, ed.version) {
                    #(#unique_ids => Some(#event_symbol),)*
                    _ => None,
                }
            }
            fn get_payload_items(&mut self) -> Option<&HashMap<&'static str, crate::modern_event::types::WinInTypeItem>> {
                if self.payload.is_some() {
                    return self.payload.as_ref();
                }

                let ed = &self.header.event_descriptor;
                match (ed.id, ed.version) {
                    #(#event_to_template => {
                        let res = self.#template_fn();
                        if let Err(e) = res {
                            ::log::warn!("Parsing of payload items failed: {e}");
                        }
                    })*
                    _ => {}
                }
                self.payload.as_ref()
            }
        }
        #templates
    }
}

fn guid_constant_name(p: &Provider) -> Ident {
    let name = p.name.to_uppercase().replace('-', "_").replace(' ', "");
    format_ident!("{}_GUID", name)
}

fn event_ident_tuple(e: &Event) -> TokenStream {
    let id = e.value;
    let version = e.version;
    quote! {
        (#id, #version)
    }
}

fn event_template_fn_ident(e: &Event) -> Option<Ident> {
    let mut name = e.template.clone()?;

    if !name.is_ascii() {
        panic!(
            "Non ASCII template id \"{}\" found, which is not supported!",
            name
        );
    }
    helper::make_function_name(&mut name);

    Some(format_ident!("parse_payload_{name}"))
}

#[cfg(test)]
mod tests {

    #[test]
    fn todo() {
        assert_eq!(5 + 1, 6)
    }
}
