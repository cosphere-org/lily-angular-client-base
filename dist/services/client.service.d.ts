import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Config } from './config.service';
import { Options, State, DataState } from './client.interface';
export declare class ClientService {
    private config;
    private http;
    /**
     * State for all GET payloads
     */
    state: Map<string, State<any>>;
    readonly baseUrl: string;
    readonly authToken: string;
    private readonly defaultAuthToken;
    /**
     * Cache time - every GET request is taken only if the last one
     * was invoked not earlier then `cacheTime` mins ago.
     * Only successful responses are cached (2xx)
     */
    private readonly cacheTime;
    constructor(config: Config, http: HttpClient);
    get<T>(endpoint: string, options?: Options): Observable<T>;
    post<T>(endpoint: string, body: any, options?: Options): Observable<T>;
    put<T>(endpoint: string, body: any, options?: Options): Observable<T>;
    delete<T>(endpoint: string, options?: Options): Observable<T>;
    getDataState<T>(endpoint: string, options?: Options): DataState<T>;
    private initState(key, options?);
    private getHttpOptions(options?);
    private getHeaders(authorizationRequired, etag?);
    private getUrl(endpoint);
    private getToken();
    private handleError(error);
}
