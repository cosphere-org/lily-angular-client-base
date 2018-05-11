/**
 * Http Client
 */
import * as Axios from 'axios';
import { Observable, Observer } from 'rxjs';
import * as _ from 'underscore';
import { HttpClient as AngularHttpCLient } from '@angular...';

interface Headers {
    'Content-Type': string;
    'Authorization'?: string;
}

@Injectable
export class HttpClient {

    constructor(private: AngularHttpCLient) {}

    get<T>(url: string, params?: any, authenticationRequired:boolean = true): Observable<T> {
        return Observable.create((o: Observer<T>) => {
            Axios.default.get(
                url,
                {
                    params,
                    headers: this.getHeaders(authenticationRequired)
                }
            ).then(response => {
                o.next(<T>response.data);
                o.complete();
            })
            .catch(error => {
                this.handleError(error);

            });

        });
    }

    post<T>(url: string, body: any, authenticationRequired:boolean = true): Observable<T> {
        return Observable.create((o: Observer<T>) => {
            Axios.default.post(
                url,
                body,
                {
                    headers: this.getHeaders(authenticationRequired)
                }
            ).then(response => {
                o.next(<T>response.data);
                o.complete();
            })
            .catch(error => {
                this.handleError(error);

            });

        });
    }

    put<T>(url: string, body: any, authenticationRequired:boolean = true): Observable<T> {
        return Observable.create((o: Observer<T>) => {
            Axios.default.put(
                url,
                body,
                {
                    headers: this.getHeaders(authenticationRequired)
                }
            ).then(response => {
                o.next(<T>response.data);
                o.complete();
            })
            .catch(error => {
                this.handleError(error);

            });

        });
    }

    delete<T>(url: string, authenticationRequired:boolean = true): Observable<T> {
        return Observable.create((o: Observer<T>) => {
            Axios.default.delete(
                url,
                {
                    headers: this.getHeaders(authenticationRequired)
                }
            ).then(response => {
                o.next(<T>response.data);
                o.complete();
            })
            .catch(error => {
                this.handleError(error);

            });

        });
    }

    public getHeaders(authenticationRequired: boolean): Headers {

        let headers: Headers = {
            'Content-Type': 'application/json'
        };
        if (authenticationRequired) {
            headers['Authorization'] = `Bearer ${this.getToken()}`;

        }

        return headers;
    }

    public getToken (): string {
        // @JAREK: how can I use localStorage here?
        // return window.localStorage.getItem('auth_token');
        return '...';
    };

    private handleError(error: any) {
        if (error.errno) {
            // -- A client-side or network error occurred. Handle it accordingly.
            console.error('An error occurred:', error.code);

        } else {
            // -- The backend returned an unsuccessful response code.
            // -- The response body may contain clues as to what went wrong,
            console.error(
                `Backend returned code ${error.response.status}, ` +
                `body was: ${error.response.data}`);
        }

    }

}
