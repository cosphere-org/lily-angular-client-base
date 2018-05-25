/**
 * Internal Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './internal.models';

@Injectable()
export class InternalDomain {
    constructor(private client: ClientService) {}

    /**
     * Change account type of any existing account
     * -------------
     *
     * Enables one to change account type of any account associated with `user_id`.
     */
    public updateAccountTypeAsAdmin(body: X.UpdateAccountTypeAsAdminBody): Observable<X.UpdateAccountTypeAsAdminResponse> {
        return this.client
            .put<X.UpdateAccountTypeAsAdminResponse>('/internal/change_account_type/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}