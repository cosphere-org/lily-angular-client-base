import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './external_apps.models';
export declare class ExternalAppsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Authorize a given external app token
     * -------------
     *
     * Can be called by the API Gateway in order to authorize every request using provided token. It must be used only for external app tokens, which are used by the external apps to make calls on behalf of a given user.
     */
    authorizeExternalAppAuthToken(): Observable<X.AuthorizeExternalAppAuthTokenResponse>;
    /**
     * Read External App Configuration
     */
    createExternalAppAuthToken(body: X.CreateExternalAppAuthTokenBody): Observable<X.CreateExternalAppAuthTokenResponse>;
    /**
     * Read External App configuration
     */
    readExternalappconf(params: X.ReadExternalappconfQuery): DataState<X.ReadExternalappconfResponse>;
    readExternalappconf2(params: X.ReadExternalappconfQuery): Observable<X.ReadExternalappconfResponse>;
}
