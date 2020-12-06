import { Injectable, Inject } from "@angular/core";
import {
  HttpClient,
  HttpParams,
  HttpHeaders,
  HttpErrorResponse,
} from "@angular/common/http";
import { Observable, throwError } from "rxjs";
import { catchError } from "rxjs/operators";
import * as _ from "underscore";

export interface Options {
  cache?: boolean;
  etag?: string;
  authorizationRequired?: boolean;
  params?: HttpParams | { [param: string]: any };
  headers?: HttpHeaders | { [header: string]: string | string[] };
  reportProgress?: boolean;
  responseMap?: string;
  ignoreBaseUrl?: boolean;
  responseType?: any;
}

export interface Config {
  baseUrl: string;
  authToken?: string;
}

@Injectable()
export class HttpService {
  readonly baseUrl: string;
  readonly authToken: string;

  private readonly defaultAuthToken: string = "auth_token";

  constructor(
    @Inject("CLIENT_CONFIG_TOKEN") private config: Config,
    private http: HttpClient
  ) {
    this.baseUrl = this.config.baseUrl;
    this.authToken = this.config.authToken || this.defaultAuthToken;
  }

  get<T>(endpoint: string, options?: Options): Observable<T> {
    const url =
      options && options.ignoreBaseUrl ? endpoint : this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .get(url, httpOptions)
      .pipe(/* retry(3), */ catchError(this.handleError)) as Observable<T>;
  }

  post<T>(endpoint: string, body: any, options?: Options): Observable<T> {
    const url =
      options && options.ignoreBaseUrl ? endpoint : this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .post(url, body, httpOptions)
      .pipe(/* retry(3), */ catchError(this.handleError)) as Observable<T>;
  }

  put<T>(endpoint: string, body: any, options?: Options): Observable<T> {
    const url =
      options && options.ignoreBaseUrl ? endpoint : this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .put(url, body, httpOptions)
      .pipe(/* retry(3), */ catchError(this.handleError)) as Observable<T>;
  }

  delete<T>(endpoint: string, options?: Options): Observable<T> {
    const url =
      options && options.ignoreBaseUrl ? endpoint : this.getUrl(endpoint);
    const httpOptions = this.getHttpOptions(options);
    return this.http
      .delete(url, httpOptions)
      .pipe(/* retry(3), */ catchError(this.handleError)) as Observable<T>;
  }

  private getHttpOptions(
    options?: Options
  ): {
    params?: HttpParams | { [param: string]: string | string[] };
    headers?: HttpHeaders | { [header: string]: string | string[] };
    reportProgress?: boolean;
    responseType?: any;
  } {
    const authorizationRequired = _.has(options, "authorizationRequired")
      ? options.authorizationRequired
      : true;
    const etag = (options && options.etag) || undefined;

    const httpOptions: {
      params?: HttpParams | { [param: string]: string | string[] };
      headers?: HttpHeaders | { [header: string]: string | string[] };
      reportProgress?: boolean;
      responseType?: any;
    } = {
      headers: this.getHeaders(authorizationRequired, etag),
    };

    if (_.has(options, "headers")) {
      // tslint:disable
      for (let key in options.headers) {
        httpOptions.headers[key] = (<any>options).headers[key];
      }
      // tslint:enable
    }

    if (_.has(options, "params")) {
      httpOptions.params = options.params;
    }

    if (_.has(options, "reportProgress")) {
      httpOptions.reportProgress = options.reportProgress;
    }

    if (_.has(options, "responseType")) {
      httpOptions.responseType = options.responseType;
    }

    return httpOptions;
  }

  private getHeaders(
    authorizationRequired: boolean,
    etag?: string
  ): { [key: string]: string } {
    const headers = {
      "Content-Type": "application/json",
    };

    if (authorizationRequired && this.getToken()) {
      headers["Authorization"] = `Bearer ${this.getToken()}`;
    }

    if (etag) {
      headers["ETag"] = etag;
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
      console.error("An error occurred:", error.error.message);
    } else {
      // The backend returned an unsuccessful response code.
      // The response body may contain clues as to what went wrong,
      console.error(
        `Backend returned code ${error.status}, ` + `body was:`,
        error.error
      );
    }

    // return an observable with a user-facing error message
    return throwError(error);
  }
}
