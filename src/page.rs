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

/// Where the page is set. Presentation only: the flow, fields, CSP and the
/// token contract are identical in every world.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum World {
    /// The neutral aiaiaiai surface every product gets.
    Ecosystem,
    /// The 0x1 evening scene, for the 0x1 client and its legacy `nilx-one`.
    OneX,
}

impl World {
    pub fn of(client_id: &str) -> Self {
        match client_id {
            "0x1" | "nilx-one" => Self::OneX,
            _ => Self::Ecosystem,
        }
    }
}

pub struct View<'a> {
    pub language: Language,
    pub world: World,
    /// `host[:port]` of this issuer, shown as the page's own address.
    pub issuer_host: &'a str,
    pub skin: Skin,
    pub product: &'a str,
    pub signed: &'a str,
    pub redirect_origin: &'a str,
    pub message: Option<Message>,
    /// A Telegram chat login: the page runs inside Telegram and hands its
    /// signed `initData` to the client through the code exchange.
    pub telegram: bool,
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
        "<input type=\"hidden\" name=\"request\" value=\"{}\">{}",
        escape(view.signed),
        if view.telegram {
            "<input type=\"hidden\" name=\"telegram_init_data\" value=\"\">"
        } else {
            ""
        }
    );
    let one = view.world == World::OneX;
    let sign_in_heading = if one {
        t("Sign in to 0x1", "Увійти в 0x1")
    } else {
        t("Sign in", "Вхід")
    };
    let (user_icon, lock_icon, enter_icon) = if one {
        (ICON_USER, ICON_LOCK, ICON_ENTER)
    } else {
        ("", "", "")
    };
    let name_label = match view.skin {
        Skin::Cell => "pub_dress",
        Skin::Slug => t("Name", "Ім'я"),
    };
    let credential_autofill = matches!(&step, Step::SignIn { .. });
    let (heading, form) = match step {
        Step::Identify { prefix, slug } => {
            // This is only the slug component, not the credential's full
            // pub_dress. Advertising it as a username confuses Password
            // AutoFill across the two-step sign-in flow on iOS.
            let field = match view.skin {
                Skin::Cell => format!(
                    "<div class=\"address-field\">{user_icon}<span class=\"digit-selector\">{select}</span>\
                     <input id=\"slug\" name=\"slug\" value=\"{slug}\" autocomplete=\"off\" autocapitalize=\"none\" \
                     spellcheck=\"false\" required autofocus></div>",
                    select = prefix_select(prefix, &DISCRIMINATORS, view.language),
                    slug = escape(slug),
                ),
                Skin::Slug => format!(
                    "<div class=\"address-field\">{user_icon}<input id=\"slug\" name=\"slug\" value=\"{}\" autocomplete=\"username\" \
                     autocapitalize=\"none\" spellcheck=\"false\" required autofocus></div>",
                    escape(slug)
                ),
            };
            (
                sign_in_heading,
                format!(
                    "<input type=\"hidden\" name=\"step\" value=\"identify\"><label for=\"slug\">{name_label}</label>{field}\
                     <button type=\"submit\">{enter_icon}{}</button>",
                    t("Continue", "Далі")
                ),
            )
        }
        Step::ChoosePrefix { slug, prefixes } => (
            sign_in_heading,
            format!(
                "<input type=\"hidden\" name=\"step\" value=\"choose\"><input type=\"hidden\" name=\"slug\" value=\"{slug}\">\
                 <label for=\"slug-view\">{name_label}</label>\
                 <div class=\"address-field\">{user_icon}<span class=\"digit-selector\">{select}</span>\
                 <input id=\"slug-view\" value=\"{slug}\" readonly></div>\
                 <button type=\"submit\">{enter_icon}{next}</button>",
                slug = escape(slug),
                select = prefix_select(prefixes[0], prefixes, view.language),
                next = t("Continue", "Далі"),
            ),
        ),
        Step::SignIn { pub_dress, slug } => (
            sign_in_heading,
            format!(
                "<input type=\"hidden\" name=\"step\" value=\"sign_in\">{username}\
                 <label for=\"password\">{password}</label>\
                 <div class=\"password-field\">{lock_icon}<input id=\"password\" name=\"password\" type=\"password\" \
                 autocomplete=\"current-password\" required autofocus></div>\
                 <button type=\"submit\">{enter_icon}{submit}</button>",
                username = username_field(view, pub_dress, slug, name_label, true),
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
                 <div class=\"password-field\">{lock_icon}<input id=\"password\" name=\"password\" type=\"password\" \
                 autocomplete=\"new-password\" minlength=\"8\" maxlength=\"128\" required autofocus></div>\
                 <label for=\"password_confirm\">{confirm}</label>\
                 <div class=\"password-field\">{lock_icon}<input id=\"password_confirm\" name=\"password_confirm\" type=\"password\" \
                 autocomplete=\"new-password\" minlength=\"8\" maxlength=\"128\" required></div>\
                 <p class=\"password-note\">{note}</p><button type=\"submit\">{enter_icon}{submit}</button>",
                assignment = escape(assignment),
                free = t("This name is free.", "Це ім'я вільне."),
                username = username_field(view, pub_dress, slug, name_label, false),
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
    let (mark, subtitle, origin) = if one {
        (
            ICON_MARK,
            format!(
                "<p class=\"world-subtitle\">{}</p>",
                t("One sign-in page", "Єдина сторінка авторизації")
            ),
            world_origin(view.issuer_host),
        )
    } else {
        ("", String::new(), String::new())
    };
    let body = format!(
        "<p class=\"surface-kicker\">{mark}aiaiaiai AIS × <span class=\"auth-product-name\">{product}</span></p>\
         <h1>{heading}</h1>{subtitle}{notice}<form class=\"identity-form ecosystem-auth-form\" method=\"post\" action=\"/authorize\">\
         {request}{form}</form>{origin}",
        product = escape(view.product),
    );
    document(
        view.language,
        view.world,
        status,
        heading,
        &body,
        view.redirect_origin,
        Scripts {
            telegram: view.telegram,
            credential_autofill,
        },
    )
}

/// The account name a password manager files the password under. It is the
/// full address in every skin, so one saved entry serves every product; the
/// `slug` skin keeps it out of sight.
fn username_field(
    view: &View<'_>,
    pub_dress: &str,
    slug: &str,
    name_label: &str,
    sign_in: bool,
) -> String {
    let address = escape(pub_dress);
    // Registration remains bound to the server-assigned address. At sign-in,
    // the cell skin can accept a different saved username; the issuer still
    // validates its full pub_dress and password, including rate limits.
    let hidden = if sign_in && matches!(view.skin, Skin::Cell) {
        String::new()
    } else {
        format!("<input type=\"hidden\" name=\"pub_dress\" value=\"{address}\">")
    };
    match view.skin {
        Skin::Cell => {
            let field = if sign_in {
                format!(
                    "<input id=\"username\" name=\"pub_dress\" type=\"text\" value=\"{address}\" \
                     autocomplete=\"off\" autocapitalize=\"none\" autocorrect=\"off\" \
                     spellcheck=\"false\" required>"
                )
            } else {
                format!(
                    "<input id=\"username\" value=\"{address}\" autocomplete=\"username\" readonly>"
                )
            };
            format!(
                "{hidden}<label for=\"username\">{name_label}</label><div class=\"address-field\">{icon}{field}</div>",
                icon = if view.world == World::OneX {
                    ICON_USER
                } else {
                    ""
                },
            )
        }
        Skin::Slug => format!(
            "{hidden}<p class=\"identity-status\">{} <strong>{}</strong></p>\
             <input id=\"username\" class=\"visually-hidden\" tabindex=\"-1\" aria-hidden=\"true\" \
             value=\"{address}\" autocomplete=\"username\" {}>",
            escape(name_label),
            escape(slug),
            if sign_in { "" } else { "readonly" }
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
    document(
        language,
        World::Ecosystem,
        status,
        heading,
        &body,
        "",
        Scripts::default(),
    )
}

/// Visible 0x1 entry for direct browser visits without an OIDC transaction.
/// The fixed host route starts the normal Core-owned state/nonce/PKCE flow;
/// AIS itself never creates a login transaction from an untrusted URL.
pub fn product_entry(language: Language, issuer_host: &str) -> Response {
    let (heading, explanation, action, note) = match language {
        Language::English => (
            "Sign in to 0x1",
            "For your Bond's security, 0x1 must start a one-time sign-in request before you enter your password.",
            "Continue through 0x1",
            "If sign-in is not available, return to 0x1. Do not create another Bond to work around it.",
        ),
        Language::Ukrainian => (
            "Вхід до 0x1",
            "Для захисту вашого Bond застосунок 0x1 має створити одноразовий запит на вхід до введення пароля.",
            "Продовжити через 0x1",
            "Якщо вхід недоступний, поверніться до 0x1. Не створюйте іншого Bond для обходу цього кроку.",
        ),
    };
    let origin = world_origin(issuer_host);
    let body = format!(
        r#"<p class="surface-kicker">{ICON_MARK}<span class="world-wordmark">aiaiaiai AIS × </span><span class="auth-product-name">0x1</span></p><h1>{heading}</h1>
           <p class="identity-status">{explanation}</p>
           <p><a class="text-action world-primary" href="https://nilx.one/api/v1/auth/aiaiaiai/start?return=%2F">{ICON_ENTER}{action}</a></p>
           <p class="identity-status">{note}</p>{origin}"#
    );
    document(
        language,
        World::OneX,
        StatusCode::OK,
        heading,
        &body,
        "",
        Scripts::default(),
    )
}

pub fn landing() -> Response {
    let body = "<p class=\"surface-kicker\">aiaiaiai AIS</p><h1>Sign in from a product</h1>\
                <p class=\"identity-status\">Products send you here when you sign in.</p>";
    document(
        Language::English,
        World::Ecosystem,
        StatusCode::OK,
        "aiaiaiai AIS",
        body,
        "",
        Scripts::default(),
    )
}

/// The page's own address under the panel: a plain fact, not a link out.
fn world_origin(issuer_host: &str) -> String {
    format!(
        "<p class=\"world-origin\">{ICON_LINK}<span>{}/0x1</span></p>",
        escape(issuer_host)
    )
}

/// Decorative evening river city behind the 0x1 panel. CSS-only motion; the
/// strict CSP allows inline SVG markup but no script and no style attributes.
const WORLD_SCENE: &str = concat!(
    "<div class=\"world-scene\" aria-hidden=\"true\">",
    "<div class=\"world-sun\"></div>",
    "<div class=\"world-cloud world-cloud--a\"></div><div class=\"world-cloud world-cloud--b\"></div>",
    "<svg class=\"world-skyline\" viewBox=\"0 0 1200 320\" preserveAspectRatio=\"xMidYMax slice\">",
    "<path class=\"world-hills\" d=\"M0 250 C120 205 220 215 330 230 C450 190 560 200 640 225 C760 195 880 180 1000 215 C1080 205 1150 210 1200 220 V320 H0Z\"/>",
    // Domes and a bell tower on the left bank.
    "<path class=\"world-city\" d=\"M90 232 V196 H104 V184 Q112 168 120 184 V196 H134 V232Z ",
    "M150 232 V150 L158 140 V118 L162 104 L166 118 V140 L174 150 V232Z ",
    "M190 232 V204 Q210 176 230 204 V232Z M240 232 V214 H262 V200 Q270 190 278 200 V232Z\"/>",
    // The bridge across the river.
    "<path class=\"world-bridge\" d=\"M560 258 Q690 196 820 258 M560 258 H960 M600 258 V242 M650 258 V222 M700 258 V212 M750 258 V214 M800 258 V246\"/>",
    // A monument on the right hills.
    "<path class=\"world-city\" d=\"M1040 214 V150 L1046 148 L1050 96 L1056 90 L1060 98 L1062 148 L1068 150 V214Z ",
    "M980 214 V196 H1010 V214Z M1090 214 V192 H1130 V214Z\"/>",
    "</svg>",
    "<div class=\"world-river\"></div>",
    "<div class=\"world-blossom world-blossom--left\"></div><div class=\"world-blossom world-blossom--right\"></div>",
    "<div class=\"world-avaia\"><span></span><span></span></div>",
    "<div class=\"world-beacon\"><span></span></div>",
    "</div>",
);

const ICON_MARK: &str = "<svg class=\"world-mark\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <path d=\"M4 10v4M8 7v10M12 4v16M16 7v10M20 10v4\"/></svg>";
const ICON_USER: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <circle cx=\"12\" cy=\"8\" r=\"4\"/><path d=\"M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6\"/></svg>";
const ICON_LOCK: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <rect x=\"5\" y=\"10\" width=\"14\" height=\"11\" rx=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3M12 14v3\"/></svg>";
const ICON_ENTER: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <path d=\"M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4M3 12h12M11 8l4 4-4 4\"/></svg>";
const ICON_LINK: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <path d=\"M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1\"/></svg>";

const CREDENTIAL_SCRIPT_TAG: &str =
    "<script src=\"/static/credential-autofill.js\" defer></script>";

pub const CREDENTIAL_AUTOFILL_SCRIPT: &str = include_str!("../static/credential-autofill.js");

const TELEGRAM_SCRIPTS: &str = "<script src=\"https://telegram.org/js/telegram-web-app.js\"></script>\
    <script src=\"/static/telegram.js\"></script>";

/// Copies Telegram's signed initData into every form of a Telegram chat login.
/// Outside Telegram it does nothing and the field stays empty.
pub const TELEGRAM_FORM_SCRIPT: &str = r#"(function () {
  var app = window.Telegram && window.Telegram.WebApp;
  if (!app || !app.initData) { return; }
  app.ready();
  app.expand();
  var fields = document.querySelectorAll('input[name="telegram_init_data"]');
  for (var i = 0; i < fields.length; i += 1) { fields[i].value = app.initData; }
})();
"#;

/// The scripts a page carries. They also decide its `script-src`, so the
/// markup and the CSP cannot disagree. Pages without a form carry none.
#[derive(Clone, Copy, Default)]
struct Scripts {
    /// Telegram's Mini App SDK and the script that copies its initData.
    telegram: bool,
    /// The same-origin password-manager AutoFill script of the sign-in step.
    credential_autofill: bool,
}

impl Scripts {
    fn tags(self) -> String {
        format!(
            "{}{}",
            if self.telegram { TELEGRAM_SCRIPTS } else { "" },
            if self.credential_autofill {
                CREDENTIAL_SCRIPT_TAG
            } else {
                ""
            },
        )
    }

    fn policy(self) -> &'static str {
        if self.telegram {
            "script-src 'self' https://telegram.org; "
        } else if self.credential_autofill {
            "script-src 'self'; "
        } else {
            ""
        }
    }
}

fn document(
    language: Language,
    world: World,
    status: StatusCode,
    title: &str,
    body: &str,
    redirect_origin: &str,
    scripts: Scripts,
) -> Response {
    let lang = if language == Language::Ukrainian {
        "uk"
    } else {
        "en"
    };
    let html = format!(
        "<!doctype html><html lang=\"{lang}\"{root_class}><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"{viewport}\">\
         <meta name=\"referrer\" content=\"no-referrer\">{theme}<title>{title} · aiaiaiai AIS</title>\
         <link rel=\"stylesheet\" href=\"/static/auth.css\"></head>\
         <body{class}>{scene}<main class=\"ecosystem-auth-panel\">{body}</main>{scripts}</body></html>",
        root_class = if world == World::OneX {
            " class=\"world-0x1-root\""
        } else {
            ""
        },
        viewport = if world == World::OneX {
            "width=device-width, initial-scale=1, viewport-fit=cover"
        } else {
            "width=device-width, initial-scale=1"
        },
        theme = if world == World::OneX {
            "<meta name=\"theme-color\" content=\"#3d4778\">"
        } else {
            ""
        },
        class = if world == World::OneX {
            " class=\"world-0x1\""
        } else {
            ""
        },
        scene = if world == World::OneX {
            WORLD_SCENE
        } else {
            ""
        },
        scripts = scripts.tags(),
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
    // A Telegram chat login also runs Telegram's Mini App SDK and the one
    // script that copies its initData into the form; the sign-in step runs the
    // same-origin AutoFill script; no other page has script.
    let script = scripts.policy();
    let csp = format!(
        "default-src 'none'; {script}style-src 'self'; font-src 'self'; form-action 'self' {redirect_origin}; \
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
