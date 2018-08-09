import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './recall.models';
export declare class RecallDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Create Recall Session
     * -------------
     *
     * Render Recall Session composed out of the sequence of Cards that should be recalled in a given order. Based on the RecallAttempt stats recommend another Card to recall in order to maximize the recall speed and success rate.
     */
    createRecallSession(body: X.CreateRecallSessionBody): Observable<X.CreateRecallSessionResponse>;
    /**
     * Read Recall Summary
     * -------------
     *
     * Read summary stats for cards and their recall_score for a given User.
     */
    readRecallSummary(): DataState<X.ReadRecallSummaryResponse>;
    readRecallSummary2(): Observable<X.ReadRecallSummaryResponse>;
}
