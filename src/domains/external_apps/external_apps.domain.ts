/**
 * External Apps Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './external_apps.models';

@Injectable()
export class ExternalAppsDomain {
    constructor(private client: ClientService) {}

    /**
     * Read External App configuration
     */
    public createExternalAppAuthToken(body: X.CreateExternalAppAuthTokenBody): Observable<X.CreateExternalAppAuthTokenResponse> {
        return this.client
            .post<X.CreateExternalAppAuthTokenResponse>('/external/tokens/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read External App configuration
     */
    public readExternalappconf(params: X.ReadExternalappconfQuery): DataState<X.ReadExternalappconfResponse> {
        return this.client.getDataState<X.ReadExternalappconfResponse>('/external/apps/', { params });
    }

}