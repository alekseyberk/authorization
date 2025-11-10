import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';
import { provideKeycloak, KeycloakService } from 'keycloak-angular';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
    provideHttpClient(),
    KeycloakService,
    provideKeycloak({
      config: {
        url: 'http://localhost:8080',
        realm: 'master',
        clientId: 'angular-frontend',
      },
      initOptions: {
        onLoad: 'check-sso',
        checkLoginIframe: false,
        pkceMethod: 'S256',
        silentCheckSsoRedirectUri: window.location.origin + '/assets/silent-check-sso.html'
        // Возвращаем silent check SSO с правильным redirect URI
      }
    })
  ]
}).catch(console.error);
