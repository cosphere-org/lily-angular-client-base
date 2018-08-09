import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './links.models';
export declare class LinksDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Remove Link
     * -------------
     *
     * Remove a Link between two cards.
     */
    deleteLink(fromCardId: any, toCardId: any): Observable<X.DeleteLinkResponse>;
    /**
     * Read or Create Link
     * -------------
     *
     * Read or Create a Link between two cards.
     */
    readOrCreateLink(body: X.ReadOrCreateLinkBody): Observable<X.ReadOrCreateLinkResponse>;
}
