import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './attempts.models';
export declare class AttemptsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Attempts By Card
     * -------------
     *
     * List Attempts for a specific Card given by its Id.
     */
    bulkReadAttemptsByCards(cardId: any): DataState<X.BulkReadAttemptsByCardsResponseEntity[]>;
    bulkReadAttemptsByCards2(cardId: any): Observable<X.BulkReadAttemptsByCardsResponseEntity[]>;
    /**
     * Create Attempt
     * -------------
     *
     * Create Attempt which is a reflection of someone's knowledge regarding a given Card.
     */
    createAttempt(body: X.CreateAttemptBody): Observable<X.CreateAttemptResponse>;
    /**
     * Update Attempt
     * -------------
     *
     * Update existing Attempt with new cells and / or style.
     */
    updateAttempt(attemptId: any, body: X.UpdateAttemptBody): Observable<X.UpdateAttemptResponse>;
}
