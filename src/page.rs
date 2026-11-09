// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! The sign-in page, rendered on the server. One flow, two skins; the markup
//! uses the class names of `packages/auth-view` so `static/auth.css` styles it.

use axum::{
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{ACCEPT_LANGUAGE, CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};

use crate::{config::Skin, store::DISCRIMINATORS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    English,
    Ukrainian,
}

impl From<&HeaderMap> for Language {
    fn from(headers: &HeaderMap) -> Self {
        let first = headers
            .get(ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if first.starts_with("uk") {
            Self::Ukrainian
        } else {
            Self::English
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    UnknownClient,
    Expired,
    Unavailable,
    InvalidAddress,
    InvalidCredentials,
    RateLimited,
    PasswordsDiffer,
    PasswordLength,
    PasswordWhitespace,
    Taken,
    NoFreePrefix,
    ChoosePrefix,
}

impl Message {
    pub fn text(self, language: Language) -> &'static str {
        use Language::{English as En, Ukrainian as Uk};
        match (self, language) {
            (Self::UnknownClient, En) => "This sign-in request did not come from a known product.",
            (Self::UnknownClient, Uk) => "Цей запит на вхід надійшов не від відомого продукту.",
            (Self::Expired, En) => {
                "This sign-in has expired. Go back to the product and start again."
            }
            (Self::Expired, Uk) => "Час на вхід минув. Поверніться до продукту й почніть знову.",
            (Self::Unavailable, En) => "Sign-in is unavailable right now. Try again shortly.",
            (Self::Unavailable, Uk) => "Вхід зараз недоступний. Спробуйте трохи згодом.",
            (Self::InvalidAddress, En) => {
                "That name cannot be used. Use letters, digits and single hyphens."
            }
            (Self::InvalidAddress, Uk) => {
                "Це ім'я не підходить. Використовуйте літери, цифри й поодинокі дефіси."
            }
            (Self::InvalidCredentials, En) => "The name or password is incorrect.",
            (Self::InvalidCredentials, Uk) => "Неправильне ім'я або пароль.",
            (Self::RateLimited, En) => "Too many attempts. Wait a little and try again.",
            (Self::RateLimited, Uk) => "Забагато спроб. Зачекайте трохи й спробуйте знову.",
            (Self::PasswordsDiffer, En) => "The passwords do not match.",
            (Self::PasswordsDiffer, Uk) => "Паролі не збігаються.",
            (Self::PasswordLength, En) => "Use a password of 8 to 128 characters.",
            (Self::PasswordLength, Uk) => "Пароль має містити від 8 до 128 символів.",
            (Self::PasswordWhitespace, En) => {
                "The password cannot start or end with a space or contain control characters."
            }
            (Self::PasswordWhitespace, Uk) => {
                "Пароль не може починатися чи закінчуватися пробілом або містити керівні символи."
            }
            (Self::Taken, En) => "That name was just taken. Choose another one.",
            (Self::Taken, Uk) => "Це ім'я щойно зайняли. Оберіть інше.",
            (Self::NoFreePrefix, En) => "That name is no longer available. Choose another one.",
            (Self::NoFreePrefix, Uk) => "Це ім'я вже недоступне. Оберіть інше.",
            (Self::ChoosePrefix, En) => "More than one account uses this name. Choose yours.",
            (Self::ChoosePrefix, Uk) => "Цим ім'ям користується кілька акаунтів. Оберіть свій.",
        }
    }
}

pub enum Step<'a> {
    /// The person names who they are.
    Identify {
        prefix: char,
        slug: &'a str,
    },
    /// `slug` products only: the slug belongs to several addresses.
    ChoosePrefix {
        slug: &'a str,
        prefixes: &'a [char],
    },
    SignIn {
        pub_dress: &'a str,
        slug: &'a str,
    },
    /// `assignment` seals the address, so the person cannot swap in a prefix
    /// AIS did not assign.
    Register {
        pub_dress: &'a str,
        slug: &'a str,
        assignment: &'a str,
    },
}

pub struct View<'a> {
    pub language: Language,
    pub skin: Skin,
    pub product: &'a str,
    pub signed: &'a str,
    pub redirect_origin: &'a str,
    pub message: Option<Message>,
}

pub fn render(view: &View<'_>, status: StatusCode, step: Step<'_>) -> Response {
    let uk = view.language == Language::Ukrainian;
    let t = |en: &'static str, ukr: &'static str| if uk { ukr } else { en };
    let notice = view
        .message
        .map(|message| {
            format!(
                "<p class=\"identity-error\" role=\"alert\">{}</p>",
                message.text(view.language)
            )
        })
        .unwrap_or_default();
    let request = format!(
        "<input type=\"hidden\" name=\"request\" value=\"{}\">",
        escape(view.signed)
    );
    let name_label = match view.skin {
        Skin::Cell => "pub_dress",
        Skin::Slug => t("Name", "Ім'я"),
    };
    let (heading, form) = match step {
        Step::Identify { prefix, slug } => {
            let field = match view.skin {
                Skin::Cell => format!(
                    "<div class=\"address-field\"><span class=\"digit-selector\">{select}</span>\
                     <input id=\"slug\" name=\"slug\" value=\"{slug}\" autocomplete=\"username\" autocapitalize=\"none\" \
                     spellcheck=\"false\" required autofocus></div>",
                    select = prefix_select(prefix, &DISCRIMINATORS, view.language),
                    slug = escape(slug),
                ),
                Skin::Slug => format!(
                    "<div class=\"address-field\"><input id=\"slug\" name=\"slug\" value=\"{}\" autocomplete=\"username\" \
                     autocapitalize=\"none\" spellcheck=\"false\" required autofocus></div>",
                    escape(slug)
                ),
            };
            (
                t("Sign in", "Вхід"),
                format!(
                    "<input type=\"hidden\" name=\"step\" value=\"identify\"><label for=\"slug\">{name_label}</label>{field}\
                     <button type=\"submit\">{}</button>",
                    t("Continue", "Далі")
                ),
            )
        }
        Step::ChoosePrefix { slug, prefixes } => (
            t("Sign in", "Вхід"),
            format!(
                "<input type=\"hidden\" name=\"step\" value=\"choose\"><input type=\"hidden\" name=\"slug\" value=\"{slug}\">\
                 <label for=\"slug-view\">{name_label}</label>\
                 <div class=\"address-field\"><span class=\"digit-selector\">{select}</span>\
                 <input id=\"slug-view\" value=\"{slug}\" readonly></div>\
                 <button type=\"submit\">{next}</button>",
                slug = escape(slug),
                select = prefix_select(prefixes[0], prefixes, view.language),
                next = t("Continue", "Далі"),
            ),
        ),
        Step::SignIn { pub_dress, slug } => (
            t("Sign in", "Вхід"),
            format!(
                "<input type=\"hidden\" name=\"step\" value=\"sign_in\">{username}\
                 <label for=\"password\">{password}</label>\
                 <div class=\"password-field\"><input id=\"password\" name=\"password\" type=\"password\" \
                 autocomplete=\"current-password\" required autofocus></div>\
                 <button type=\"submit\">{submit}</button>",
                username = username_field(view, pub_dress, slug, name_label),
                password = t("Password", "Пароль"),
                submit = t("Sign in", "Увійти"),
            ),
        ),
        Step::Register {
            pub_dress,
            slug,
            assignment,
        } => (
            t("Create an account", "Створення акаунта"),
            format!(
                "<input type=\"hidden\" name=\"step\" value=\"register\">\
                 <input type=\"hidden\" name=\"assignment\" value=\"{assignment}\">\
                 <p class=\"identity-status\">{free}</p>{username}\
                 <label for=\"password\">{password}</label>\
                 <div class=\"password-field\"><input id=\"password\" name=\"password\" type=\"password\" \
                 autocomplete=\"new-password\" minlength=\"8\" maxlength=\"128\" required autofocus></div>\
                 <label for=\"password_confirm\">{confirm}</label>\
                 <div class=\"password-field\"><input id=\"password_confirm\" name=\"password_confirm\" type=\"password\" \
                 autocomplete=\"new-password\" minlength=\"8\" maxlength=\"128\" required></div>\
                 <p class=\"password-note\">{note}</p><button type=\"submit\">{submit}</button>",
                assignment = escape(assignment),
                free = t("This name is free.", "Це ім'я вільне."),
                username = username_field(view, pub_dress, slug, name_label),
                password = t("Password", "Пароль"),
                confirm = t("Repeat the password", "Повторіть пароль"),
                note = t(
                    "The password is the key to your account in every product. Keep it in a password manager: without another linked method there is no recovery.",
                    "Пароль — ключ до вашого акаунта в усіх продуктах. Збережіть його в менеджері паролів: без іншого підключеного способу відновлення немає."
                ),
                submit = t("Create the account", "Створити акаунт"),
            ),
        ),
    };
    let body = format!(
        "<p class=\"surface-kicker\">aiaiaiai AIS × <span class=\"auth-product-name\">{product}</span></p>\
         <h1>{heading}</h1>{notice}<form class=\"identity-form ecosystem-auth-form\" method=\"post\" action=\"/authorize\">\
         {request}{form}</form>",
        product = escape(view.product),
    );
    document(view.language, status, heading, &body, view.redirect_origin)
}

/// The account name a password manager files the password under. It is the
/// full address in every skin, so one saved entry serves every product; the
/// `slug` skin keeps it out of sight.
fn username_field(view: &View<'_>, pub_dress: &str, slug: &str, name_label: &str) -> String {
    let hidden = format!(
        "<input type=\"hidden\" name=\"pub_dress\" value=\"{}\">",
        escape(pub_dress)
    );
    match view.skin {
        Skin::Cell => format!(
            "{hidden}<label for=\"username\">{name_label}</label><div class=\"address-field\">\
             <input id=\"username\" value=\"{}\" autocomplete=\"username\" readonly></div>",
            escape(pub_dress)
        ),
        Skin::Slug => format!(
            "{hidden}<p class=\"identity-status\">{} <strong>{}</strong></p>\
             <input class=\"visually-hidden\" tabindex=\"-1\" aria-hidden=\"true\" value=\"{}\" autocomplete=\"username\" readonly>",
            escape(name_label),
            escape(slug),
            escape(pub_dress)
        ),
    }
}

fn prefix_select(selected: char, prefixes: &[char], language: Language) -> String {
    let label = if language == Language::Ukrainian {
        "Префікс"
    } else {
        "Prefix"
    };
    let options: String = prefixes
        .iter()
        .map(|prefix| {
            let mark = if *prefix == selected { " selected" } else { "" };
            format!("<option value=\"{prefix}\"{mark}>0x{prefix}</option>")
        })
        .collect();
    format!("<select name=\"prefix\" aria-label=\"{label}\">{options}</select>")
}

pub fn error_page(language: Language, status: StatusCode, message: Message) -> Response {
    let heading = if language == Language::Ukrainian {
        "Вхід"
    } else {
        "Sign in"
    };
    let body = format!(
        "<p class=\"surface-kicker\">aiaiaiai AIS</p><h1>{heading}</h1><p class=\"identity-error\" role=\"alert\">{}</p>",
        message.text(language)
    );
    document(language, status, heading, &body, "")
}

pub fn landing() -> Response {
    let body = "<p class=\"surface-kicker\">aiaiaiai AIS</p><h1>Sign in from a product</h1>\
                <p class=\"identity-status\">Products send you here when you sign in.</p>";
    document(Language::English, StatusCode::OK, "aiaiaiai AIS", body, "")
}

fn document(
    language: Language,
    status: StatusCode,
    title: &str,
    body: &str,
    redirect_origin: &str,
) -> Response {
    let lang = if language == Language::Ukrainian {
        "uk"
    } else {
        "en"
    };
    let html = format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\"><title>{title} · aiaiaiai AIS</title>\
         <link rel=\"stylesheet\" href=\"/static/auth.css\"></head>\
         <body><main class=\"ecosystem-auth-panel\">{body}</main></body></html>"
    );
    let mut response = (status, html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    secure_headers(headers);
    // Browsers apply form-action to the redirect after the post, so the
    // client's own origin is an allowed destination.
    let csp = format!(
        "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self' {redirect_origin}; \
         frame-ancestors 'none'; base-uri 'none'"
    );
    if let Ok(value) = HeaderValue::from_str(csp.trim()) {
        headers.insert("content-security-policy", value);
    }
    response
}

pub fn secure_headers(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
}

pub fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }
}
