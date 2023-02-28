from dataclasses import dataclass, field

from flask import Markup, url_for


@dataclass
class NavbarLink:
    href: str
    text: str
    is_form: bool = False
    roles: list[str] = field(default_factory=list)
    initialized: bool = False

    def init(self) -> None:
        if self.initialized:
            return
        self.href = url_for(self.href)
        self.initialized = True

    def to_html(self, csrf_token: str, is_active: bool = False) -> str:
        decor_class = 'button is-primary is-large'
        is_active_str = 'is-hovered' if is_active else ''
        if self.is_form:
            is_active_str = 'is-hovered' if is_active else ''
            return Markup(
                f"""
                <span class="navbar-item">
                <form action="{self.href}" method="POST">
                    <input type="hidden" name="csrf_token" value="{ csrf_token }" />
                    <input class="{is_active_str} {decor_class}" type="submit" value="{self.text}" >
                    
                    </input>
                </form>
                </span>
                """
            )
        return Markup(
            f"""
            <span class="navbar-item">
                <a 
                class="{decor_class} {is_active_str}" 
                href="{self.href}">
                    {self.text}
                </a>
            </span>
            """
        )


navbar_items = [
    NavbarLink(href='views.login', text='Log in', roles=['anon']),
    NavbarLink(
        is_form=True,
        href='views.logout',
        text='Log out',
        roles=['user', 'admin'],
    ),
    NavbarLink(
        is_form=True,
        href='views.logout_all',
        text='Log out all',
        roles=['user', 'admin'],
    ),
    NavbarLink(
        href='views.profile',
        text='Profile',
        roles=['user', 'admin'],
    ),
    NavbarLink(href='users.index_view', text='Admin', roles=['admin']),
    NavbarLink(href='views.register', text='Register', roles=['anon']),
    NavbarLink(
        href='views.history',
        text='History',
        roles=['user', 'admin'],
    ),
    NavbarLink(href='views.index', text='Home', roles=['user', 'admin']),
]
