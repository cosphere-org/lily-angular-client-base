import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './nouns.models';
export declare class NounsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Bulk Read Noun Project Icons
     */
    bulkReadIcons(params: X.BulkReadIconsQuery): DataState<X.BulkReadIconsResponseEntity[]>;
    bulkReadIcons2(params: X.BulkReadIconsQuery): Observable<X.BulkReadIconsResponseEntity[]>;
}
