use quote::{quote, quote_spanned, ToTokens};
use super::attributes::HookAttrs;
use proc_macro2::Span;

pub fn generate(name: &syn::Ident, orig: &syn::Ident, attrs: &HookAttrs) -> impl ToTokens {
    let _install_fn = quote::format_ident!("{}_sunset_internal_install_hook", name);
    let replace = ({
                        attrs.offset.as_ref().map(|offset|{
                            quote! {
                                #offset
                            }
                        })
                    })
                    .unwrap_or_else(||{
                        quote_spanned!(Span::call_site() =>
                            compile_error!("Missing 'offset' item in hook macro");
                        )
                    });

    if attrs.inline {
        quote!{
            pub fn #_install_fn() {
                unsafe {
                    ::sunset::inline_hook(
                        (#replace as usize),
                        (#name),
                    ).unwrap()
                }
            }
        }
    } else {
        quote!{
            #[allow(non_upper_case_globals)]
            pub static mut #orig: usize = #replace;

            pub fn #_install_fn() {
                unsafe {
                    ::sunset::replace_hook(
                        &mut #orig, 
                        #name as *const (),
                    )
                }
            }
        }
    }
}