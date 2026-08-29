use syn::parse::{Parse, ParseStream};
use syn::{parenthesized, token, Token};
mod kw {
    syn::custom_keyword!(inline);
    syn::custom_keyword!(extended_inline);
    syn::custom_keyword!(offset);
}

#[derive(Default, Debug)]
pub struct HookAttrs {
    pub offset: Option<syn::Expr>,
    pub inline: bool,
    pub extended_inline: bool,
}

fn merge(attr1: HookAttrs, attr2: HookAttrs) -> HookAttrs {
    let (
        HookAttrs {
            offset: o1,
            inline: i1,
            extended_inline: ei1,
        },
        HookAttrs {
            offset: o2,
            inline: i2,
            extended_inline: ei2,
        },
    ) = (attr1, attr2);

    HookAttrs {
        offset: o1.or(o2),
        inline: i1 || i2,
        extended_inline: ei1 || ei2,
    }
}

impl Parse for HookAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let look = input.lookahead1();
        let attr = if look.peek(kw::offset) {
            let MetaItem::<kw::offset, syn::Expr> { item: offset, .. } = input.parse()?;

            let mut a = HookAttrs::default();
            a.offset = Some(offset);
            a
        } else if look.peek(kw::inline) {
            let _: kw::inline = input.parse()?;
            let mut a = HookAttrs::default();
            a.inline = true;
            a
        } else if look.peek(kw::extended_inline) {
            let _: kw::extended_inline = input.parse()?;
            let mut a = HookAttrs::default();
            a.extended_inline = true;
            a
        } else {
            return Err(look.error());
        };

        Ok(if input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            if input.is_empty() {
                attr
            } else {
                merge(attr, input.parse()?)
            }
        } else {
            attr
        })
    }
}

#[derive(Debug, Clone)]
pub struct MetaItem<Keyword: Parse, Item: Parse> {
    #[allow(dead_code)]
    pub ident: Keyword,
    pub item: Item,
}

impl<Keyword: Parse, Item: Parse> Parse for MetaItem<Keyword, Item> {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident = input.parse()?;
        let item = if input.peek(token::Paren) {
            let content;
            parenthesized!(content in input);
            content.parse()?
        } else {
            input.parse::<Token![=]>()?;
            input.parse()?
        };

        Ok(Self { ident, item })
    }
}
