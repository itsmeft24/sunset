#![feature(abi_thiscall)]

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{parse_macro_input, parse_quote, Stmt};
use syn::{punctuated::Punctuated, token::Comma, BareFnArg, FnArg};

mod attributes;
mod install_fn;

// copied from https://github.com/ultimate-research/skyline-rs/blob/master/skyline_macro/src/lib.rs
fn into_bare_args(args: &Punctuated<FnArg, Comma>) -> Punctuated<BareFnArg, Comma> {
    args.iter()
        .map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                BareFnArg {
                    attrs: pat_type.attrs.clone(),
                    name: None,
                    ty: (*pat_type.ty).clone(),
                }
            } else {
                todo!()
            }
        })
        .collect()
}

fn get_arg_pats(args: &Punctuated<FnArg, Comma>) -> Punctuated<syn::Pat, Comma> {
    args.iter()
        .map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                (*pat_type.pat).clone()
            } else {
                todo!()
            }
        })
        .collect()
}

#[proc_macro_attribute]
pub fn from_offset(attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut fn_sig = parse_macro_input!(input as syn::ForeignItemFn);
    let offset = parse_macro_input!(attr as syn::Expr);

    let mut inner_fn_type: syn::TypeBareFn = parse_quote!(extern "C" fn());

    inner_fn_type.abi = fn_sig.sig.abi.clone();

    inner_fn_type.output = fn_sig.sig.output.clone();
    inner_fn_type.variadic = fn_sig.sig.variadic.clone();
    inner_fn_type.inputs = into_bare_args(&fn_sig.sig.inputs);

    let visibility = fn_sig.vis;
    fn_sig.sig.unsafety = Some(syn::token::Unsafe {
        span: Span::call_site(),
    });

    let sig = fn_sig.sig;
    let args = get_arg_pats(&sig.inputs);

    // Generate a shim for the function at the offset
    quote!(
        #visibility #sig {
            let inner = core::mem::transmute::<_,#inner_fn_type>(#offset as usize);
            inner(
                #args
            )
        }
    )
    .into()
}

fn remove_mut(arg: &syn::FnArg) -> syn::FnArg {
    let mut arg = arg.clone();

    if let syn::FnArg::Typed(ref mut arg) = arg {
        if let syn::Pat::Ident(ref mut arg) = *arg.pat {
            arg.by_ref = None;
            arg.mutability = None;
            arg.subpat = None;
        }
    }

    arg
}

#[proc_macro_attribute]
pub fn hook(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let mut mod_fn = parse_macro_input!(input as syn::ItemFn);
    let attrs = parse_macro_input!(attrs as attributes::HookAttrs);
    let mut output = TokenStream2::new();

    // force cdecl if inline
    if attrs.inline {
        mod_fn.sig.abi = Some(syn::Abi {
            extern_token: syn::token::Extern { span: Span::call_site() },
            name: Some(syn::LitStr::new("cdecl", Span::call_site()))
        });
    }

    let abi_token = mod_fn.sig.abi.clone().unwrap();

    let args_tokens = mod_fn.sig.inputs.iter().map(remove_mut);
    let return_tokens = mod_fn.sig.output.to_token_stream();

    let _orig_fn = quote::format_ident!(
        "{}_sunset_internal_original_fn",
        mod_fn.sig.ident
    );

    // allow original!
    if !attrs.inline {
        let orig_stmt: Stmt = parse_quote! {
            #[allow(unused_macros)]
            macro_rules! original {
                () => {
                    unsafe {
                        core::mem::transmute::<_,  #abi_token fn(#(#args_tokens),*) #return_tokens>(#_orig_fn as *const())
                    }
                }
            }
        };
        mod_fn.block.stmts.insert(0, orig_stmt);
        let orig_stmt: Stmt = parse_quote! {
            #[allow(unused_macros)] 
            macro_rules! call_original {
                ($($args:expr),* $(,)?) => {
                    original!()($($args),*)
                }
            }
        };
        mod_fn.block.stmts.insert(1, orig_stmt);
    }

    mod_fn.to_tokens(&mut output);

    let install_fn = install_fn::generate(&mod_fn.sig.ident, &_orig_fn, &attrs);

    install_fn.to_tokens(&mut output);

    output.into()
}

#[proc_macro]
pub fn install_hook(input: TokenStream) -> TokenStream {
    let mut path = parse_macro_input!(input as syn::Path);

    let last_seg = path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_sunset_internal_install_hook", last_seg.ident);

    quote!(
        #path();
    ).into()
}
