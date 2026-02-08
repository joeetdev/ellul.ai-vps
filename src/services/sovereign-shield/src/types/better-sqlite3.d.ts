/**
 * Minimal type declarations for better-sqlite3
 * Used by VPS services that run on the server with their own dependencies
 */

declare module 'better-sqlite3' {
  interface Statement<BindParameters extends unknown[] = unknown[]> {
    run(...params: BindParameters): RunResult;
    get(...params: BindParameters): unknown;
    all(...params: BindParameters): unknown[];
  }

  interface RunResult {
    changes: number;
    lastInsertRowid: number | bigint;
  }

  interface Database {
    prepare<T = unknown>(source: string): Statement;
    exec(source: string): this;
    pragma(source: string, options?: { simple?: boolean }): unknown;
    close(): void;
  }

  interface DatabaseConstructor {
    new (filename: string, options?: Record<string, unknown>): Database;
    (filename: string, options?: Record<string, unknown>): Database;
  }

  const Database: DatabaseConstructor;
  export = Database;
}
