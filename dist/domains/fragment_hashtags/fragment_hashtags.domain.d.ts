import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './fragment_hashtags.models';
export declare class FragmentHashtagsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Hashtags
     * -------------
     *
     * List Hashtags
     */
    bulkReadFragmentHashtags(params: X.BulkReadFragmentHashtagsQuery): DataState<X.BulkReadFragmentHashtagsResponseEntity[]>;
    bulkReadFragmentHashtags2(params: X.BulkReadFragmentHashtagsQuery): Observable<X.BulkReadFragmentHashtagsResponseEntity[]>;
    /**
     * List Published Hashtags
     * -------------
     *
     * List Published Hashtags
     */
    bulkReadPublishedFragmentHashtags(params: X.BulkReadPublishedFragmentHashtagsQuery): DataState<X.BulkReadPublishedFragmentHashtagsResponseEntity[]>;
    bulkReadPublishedFragmentHashtags2(params: X.BulkReadPublishedFragmentHashtagsQuery): Observable<X.BulkReadPublishedFragmentHashtagsResponseEntity[]>;
}
