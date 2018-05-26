import { NgModule, ModuleWithProviders, Injector } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';

/** Domains */
import { AccountSettingsDomain } from './domains/account_settings/index';
import { AccountsDomain } from './domains/accounts/index';
import { AttemptStatsDomain } from './domains/attempt_stats/index';
import { AttemptsDomain } from './domains/attempts/index';
import { AuthTokensDomain } from './domains/auth_tokens/index';
import { CardsDomain } from './domains/cards/index';
import { CategoriesDomain } from './domains/categories/index';
import { ContactsDomain } from './domains/contacts/index';
import { DonationsDomain } from './domains/donations/index';
import { ExternalAppsDomain } from './domains/external_apps/index';
import { FocusRecordsDomain } from './domains/focus_records/index';
import { FragmentHashtagsDomain } from './domains/fragment_hashtags/index';
import { FragmentWordsDomain } from './domains/fragment_words/index';
import { FragmentsDomain } from './domains/fragments/index';
import { GeometriesDomain } from './domains/geometries/index';
import { HashtagsDomain } from './domains/hashtags/index';
import { InternalDomain } from './domains/internal/index';
import { InvoicesDomain } from './domains/invoices/index';
import { LinksDomain } from './domains/links/index';
import { MediaitemsDomain } from './domains/mediaitems/index';
import { NotificationsDomain } from './domains/notifications/index';
import { PathsDomain } from './domains/paths/index';
import { PaymentCardsDomain } from './domains/payment_cards/index';
import { PaymentsDomain } from './domains/payments/index';
import { RecallDomain } from './domains/recall/index';
import { SubscriptionsDomain } from './domains/subscriptions/index';
import { TasksDomain } from './domains/tasks/index';
import { WordsDomain } from './domains/words/index';

/** Services */
import {
  APIService,
  ClientService,
  ConfigService,
  Config
} from './services/index';

@NgModule({
  imports: [HttpClientModule],
  exports: [HttpClientModule]
})
export class ClientModule {
  /** Should be called only in the root app module, `AppModule` */
  static forRoot(config: Config): ModuleWithProviders {
    return {
      ngModule: ClientModule,
      providers: [
        {
          provide: ConfigService,
          useFactory: () => new ConfigService(config)
        },
        ClientService,

        // Domains
        AccountSettingsDomain,
        AccountsDomain,
        AttemptStatsDomain,
        AttemptsDomain,
        AuthTokensDomain,
        CardsDomain,
        CategoriesDomain,
        ContactsDomain,
        DonationsDomain,
        ExternalAppsDomain,
        FocusRecordsDomain,
        FragmentHashtagsDomain,
        FragmentWordsDomain,
        FragmentsDomain,
        GeometriesDomain,
        HashtagsDomain,
        InternalDomain,
        InvoicesDomain,
        LinksDomain,
        MediaitemsDomain,
        NotificationsDomain,
        PathsDomain,
        PaymentCardsDomain,
        PaymentsDomain,
        RecallDomain,
        SubscriptionsDomain,
        TasksDomain,
        WordsDomain,

        // Facade
        APIService,
      ]
    };
  }
}
