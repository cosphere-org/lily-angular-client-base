import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './processes.models';
export declare class ProcessesDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Create Deletion Process
     */
    createDeletionProcess(body: X.CreateDeletionProcessBody): Observable<X.CreateDeletionProcessResponse>;
    /**
     * Create Download Process
     */
    createDownloadProcess(body: X.CreateDownloadProcessBody): Observable<X.CreateDownloadProcessResponse>;
    /**
     * Create Media Lock
     */
    createMediaLock(body: X.CreateMediaLockBody): Observable<X.CreateMediaLockResponse>;
    /**
     * Create Upload Process
     */
    createUploadProcess(body: X.CreateUploadProcessBody): Observable<X.CreateUploadProcessResponse>;
    /**
     * Read invariants for a given uri
     */
    readInvariants(params: X.ReadInvariantsQuery): DataState<X.ReadInvariantsResponse>;
    readInvariants2(params: X.ReadInvariantsQuery): Observable<X.ReadInvariantsResponse>;
    /**
     * Create Media Lock
     */
    readProcessState(params: X.ReadProcessStateQuery): DataState<X.ReadProcessStateResponse>;
    readProcessState2(params: X.ReadProcessStateQuery): Observable<X.ReadProcessStateResponse>;
    /**
     * Sign Process dedicated to upload and conversion of media file
     */
    signProcess(params: X.SignProcessQuery): DataState<X.SignProcessResponse>;
    signProcess2(params: X.SignProcessQuery): Observable<X.SignProcessResponse>;
    /**
     * Watch conversion status
     * -------------
     *
     * Endpoint called by the external conversion service.
     */
    watchConversionStatus(waiterId: any, params: X.WatchConversionStatusQuery): DataState<X.WatchConversionStatusResponse>;
    watchConversionStatus2(waiterId: any, params: X.WatchConversionStatusQuery): Observable<X.WatchConversionStatusResponse>;
}
