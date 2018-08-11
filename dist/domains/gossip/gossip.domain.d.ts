import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './gossip.models';
export declare class GossipDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Bulk Read all supported spoken languages
     */
    bulkReadSpeechLanguages(): DataState<X.BulkReadSpeechLanguagesResponseEntity[]>;
    bulkReadSpeechLanguages2(): Observable<X.BulkReadSpeechLanguagesResponseEntity[]>;
    /**
     * Bulk Read all supported voice languages
     */
    bulkReadTextLanguages(): DataState<X.BulkReadTextLanguagesResponseEntity[]>;
    bulkReadTextLanguages2(): Observable<X.BulkReadTextLanguagesResponseEntity[]>;
    /**
     * Detect spoken language
     */
    detectSpeechLanguages(body: X.DetectSpeechLanguagesBody): Observable<X.DetectSpeechLanguagesResponse>;
    /**
     * Detect written language
     */
    detectTextLanguages(body: X.DetectTextLanguagesBody): Observable<X.DetectTextLanguagesResponse>;
}
