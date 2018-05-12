import { NgModule, ModuleWithProviders } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';

/** Domains */
import { CardsDomain } from './domains/cards/index';

/** Services */
import {
  CoSphereService,
  ClientService,
  ConfigService,
  Config
} from './services/index';

@NgModule({
  imports: [HttpClientModule]
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
        CardsDomain,

        // Facade
        CoSphereService,
      ]
    };
  }
}
