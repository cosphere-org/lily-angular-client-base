/**
 * Account Settings Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './account_settings.models';

@Injectable()
export class AccountSettingsDomain {
    constructor(private client: ClientService) {}

    /**
     * Update Account Settings
     */
    public updateAccountsetting(body: X.UpdateAccountsettingBody): Observable<X.UpdateAccountsettingResponse> {
        return this.client
            .put<X.UpdateAccountsettingResponse>('/account/settings/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Account Settings
     */
    public readAccountsetting(): DataState<X.ReadAccountsettingResponse> {
        return this.client.getDataState<X.ReadAccountsettingResponse>('/account/settings/');
    }

}