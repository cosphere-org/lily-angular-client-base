import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './account_settings.models';
export declare class AccountSettingsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Read Account Settings
     */
    readAccountsetting(): DataState<X.ReadAccountsettingResponse>;
    readAccountsetting2(): Observable<X.ReadAccountsettingResponse>;
    /**
     * Update Account Settings
     */
    updateAccountsetting(body: X.UpdateAccountsettingBody): Observable<X.UpdateAccountsettingResponse>;
}
