import { Injectable } from '@angular/core';
import {
  HttpClient,
  HttpParams,
  HttpHeaders,
  HttpErrorResponse
} from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { Subject } from 'rxjs';
import { Observable } from 'rxjs';
import { catchError, retry, map } from 'rxjs/operators';
// FIXME - uncomment it when use rxjs 6.0.0
// import { throwError } from 'rxjs';
import * as _ from 'underscore';

import { ConfigService } from './config.service';
import { Options, State, DataState, RequestState } from './client.interface';

@Injectable()
export class ClientService {
  /**
   * State for all GET payloads
   */
  state: State<any> = {};

  readonly baseUrl: string;
  readonly authToken: string;

  private readonly defaultAuthToken: string = 'auth_token';

  /**
   * Cache time - every GET request is taken only if the last one
   * was invoked not earlier then `cacheTime` mins ago.
   * Only successful responses are cached (2xx)
   */
  private readonly cacheTime = 1000 * 60 * 5; // 5 mins

  constructor(private configService: ConfigService, private http: HttpClient) {
    this.baseUrl = this.configService.config.baseUrl;
    this.authToken =
      this.configService.config.authToken || this.defaultAuthToken;
  }

  get<T>(endpoint: string, options?: Options): Observable<T> {
    const url = this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .get(url, httpOptions)
      .pipe(retry(3), catchError(this.handleError)) as Observable<T>;
  }

  post<T>(endpoint: string, body: any, options?: Options): Observable<T> {
    const url = this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .post(url, body, httpOptions)
      .pipe(retry(3), catchError(this.handleError)) as Observable<T>;
  }

  put<T>(endpoint: string, body: any, options?: Options): Observable<T> {
    const url = this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .put(url, body, httpOptions)
      .pipe(retry(3), catchError(this.handleError)) as Observable<T>;
  }

  delete<T>(endpoint: string, options?: Options): Observable<T> {
    const url = this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .delete(url, httpOptions)
      .pipe(retry(3), catchError(this.handleError)) as Observable<T>;
  }

  getDataState<T>(endpoint: string, options?: Options): DataState<T> {
    this.initState(endpoint);

    let cache = true;
    let params: HttpParams | { [param: string]: string | string[] };

    if (_.has(options, 'cache')) {
      cache = options.cache;
    }

    if (_.has(options, 'params')) {
      params = options.params;
    }

    // Do not allow invoke the same GET request while one is pending
    if (this.state[endpoint].requestState.pending && !_.isEmpty(params)) {
      return this.state[endpoint].dataState;
    }

    const currentTime = +new Date();
    if (
      currentTime - this.state[endpoint].requestState.cachedAt >
        this.cacheTime ||
      !_.isEmpty(params) ||
      !cache
    ) {
      this.state[endpoint].requestState.pending = true;
      this.get(endpoint, options)
        .pipe(
          map(data => options.responseMap ? data[options.responseMap] : data)
        )
        .subscribe(
          data => {
            this.state[endpoint].dataState.data$.next(data);
            this.state[endpoint].dataState.isData$.next(!_.isEmpty(data));
            this.state[endpoint].dataState.loading$.next(false);
            this.state[endpoint].requestState.pending = false;
            this.state[endpoint].requestState.cachedAt = currentTime;
          },
          err => {
            this.state[endpoint].dataState.isData$.next(false);
            this.state[endpoint].dataState.data$.error({});
            this.state[endpoint].dataState.loading$.next(false);
            this.state[endpoint].requestState.pending = false;
          }
        );
    } else {
      this.state[endpoint].dataState.loading$.next(false);
    }

    return this.state[endpoint].dataState;
  }

  private initState(endpoint: string): void {
    if (!this.state[endpoint]) {
      this.state[endpoint] = {
        dataState: {
          loading$: new BehaviorSubject(true),
          isData$: new BehaviorSubject(false),
          data$: new BehaviorSubject({})
        },
        requestState: {
          cachedAt: 0,
          pending: false
        }
      };
    } else {
      this.state[endpoint].dataState.loading$.next(true);
    }
  }

  private getHttpOptions(
    options?: Options
  ): {
    params?: HttpParams | { [param: string]: string | string[] };
    headers?: HttpHeaders | { [header: string]: string | string[] };
    reportProgress?: boolean;
  } {
    const authRequired = (options && options.authRequired) || true;
    const etag = (options && options.etag) || undefined;

    let httpOptions = {
      headers: this.getHeaders(authRequired, etag)
    };

    if (_.has(options, 'headres')) {
      // tslint:disable
      for (let key in options.headers) {
        httpOptions.headers.append(key, (<any>options).headers[key]);
      }
      // tslint:enable
    }

    if (_.has(options, 'params')) {
      Object.assign(httpOptions, options.params);
    }

    if (_.has(options, 'reportProgress')) {
      Object.assign(httpOptions, options.reportProgress);
    }

    return httpOptions;
  }

  private getHeaders(
    authenticationRequired: boolean,
    etag?: string
  ): HttpHeaders {
    let headers = new HttpHeaders({
      'Content-Type': 'application/json'
    });

    if (authenticationRequired) {
      headers.append('Authorization', `Bearer ${this.getToken()}`);
    }

    if (etag) {
      headers.append('ETag', etag);
    }

    return headers;
  }

  private getUrl(endpoint: string): string {
    return `${this.baseUrl}${endpoint}`;
  }

  private getToken(): string {
    return localStorage.getItem(this.authToken);
  }

  private handleError(error: HttpErrorResponse) {
    if (error.error instanceof ErrorEvent) {
      // A client-side or network error occurred. Handle it accordingly.
      console.error('An error occurred:', error.error.message);
    } else {
      // The backend returned an unsuccessful response code.
      // The response body may contain clues as to what went wrong,
      console.error(
        `Backend returned code ${error.status}, ` + `body was: ${error.error}`
      );
    }
    // return an observable with a user-facing error message
    return Observable.throw('Something bad happened; please try again later.');
    // FIXME - uncomment it when use rxjs 6.0.0
    // return throwError(
    //   'Something bad happened; please try again later.');
  }
}
