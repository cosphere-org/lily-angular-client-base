import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './bricks.models';
export declare class BricksDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Bulk Read Bricks Game Attempts
     */
    bulkReadGameattempts(gameId: any): DataState<X.BulkReadGameattemptsResponseEntity[]>;
    bulkReadGameattempts2(gameId: any): Observable<X.BulkReadGameattemptsResponseEntity[]>;
    /**
     * Bulk Read Game
     */
    bulkReadGames(): DataState<X.BulkReadGamesResponseEntity[]>;
    bulkReadGames2(): Observable<X.BulkReadGamesResponseEntity[]>;
    /**
     * Create Game
     */
    createGame(body: X.CreateGameBody): Observable<X.CreateGameResponse>;
    /**
     * Create Bricks Game Attempt
     */
    createGameattempt(gameId: any, body: X.CreateGameattemptBody): Observable<X.CreateGameattemptResponse>;
    /**
     * Delete Game
     */
    deleteGame(gameId: any): Observable<X.DeleteGameResponse>;
    /**
     * Read Game
     */
    readGame(gameId: any): DataState<X.ReadGameResponse>;
    readGame2(gameId: any): Observable<X.ReadGameResponse>;
    /**
     * Update Game
     */
    updateGame(gameId: any, body: X.UpdateGameBody): Observable<X.UpdateGameResponse>;
}
