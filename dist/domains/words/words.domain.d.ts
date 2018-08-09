import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './words.models';
export declare class WordsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Words
     * -------------
     *
     * List Words by first character. It allows one to fetch list of words by first character.
     */
    bulkReadWords(params: X.BulkReadWordsQuery): DataState<X.BulkReadWordsResponseEntity[]>;
    bulkReadWords2(params: X.BulkReadWordsQuery): Observable<X.BulkReadWordsResponseEntity[]>;
}
