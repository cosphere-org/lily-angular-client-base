import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './cards.models';
export declare class CardsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Remove Card
     * -------------
     *
     * Remove list of Cards specified by their ids.
     */
    bulkDeleteCards(params: X.BulkDeleteCardsQuery): Observable<X.BulkDeleteCardsResponse>;
    /**
     * Bulk Read Multiple Cards
     * -------------
     *
     * List subset of Cards depending on various filtering flags.
     */
    bulkReadCards(params: X.BulkReadCardsQuery): DataState<X.BulkReadCardsResponseEntity[]>;
    bulkReadCards2(params: X.BulkReadCardsQuery): Observable<X.BulkReadCardsResponseEntity[]>;
    bulkReadGeometriesOnly2(params: X.BulkReadCardsQuery): Observable<X.BulkReadCardsResponseEntity[]>;
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    createCard(body: X.CreateCardBody): Observable<X.CreateCardResponse>;
    /**
     * Read Card by Id
     * -------------
     *
     * Read Card by `id`.
     */
    readCard(cardId: any): DataState<X.ReadCardResponse>;
    readCard2(cardId: any, params?: any): Observable<X.ReadCardResponse>;
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    updateCard(cardId: any, body: X.UpdateCardBody): Observable<X.UpdateCardResponse>;
}
