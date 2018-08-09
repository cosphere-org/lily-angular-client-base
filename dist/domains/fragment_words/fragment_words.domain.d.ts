import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './fragment_words.models';
export declare class FragmentWordsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Words
     * -------------
     *
     * List Words
     */
    bulkReadFragmentWords(params: X.BulkReadFragmentWordsQuery): DataState<X.BulkReadFragmentWordsResponseEntity[]>;
    bulkReadFragmentWords2(params: X.BulkReadFragmentWordsQuery): Observable<X.BulkReadFragmentWordsResponseEntity[]>;
    /**
     * List Published Words
     * -------------
     *
     * List Published Words
     */
    bulkReadPublishedFragmentWords(params: X.BulkReadPublishedFragmentWordsQuery): DataState<X.BulkReadPublishedFragmentWordsResponseEntity[]>;
    bulkReadPublishedFragmentWords2(params: X.BulkReadPublishedFragmentWordsQuery): Observable<X.BulkReadPublishedFragmentWordsResponseEntity[]>;
}
