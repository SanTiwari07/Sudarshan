import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

/**
 * There was no error boundary anywhere in the app, so a single exception in any
 * page unmounted the whole React tree to a blank white screen with no recovery
 * path. For an analyst tool that renders untrusted, frequently malformed data
 * derived from hostile APKs, that failure mode is a matter of when, not if.
 *
 * Scoped per route (see App.tsx) so a crash in one view leaves the shell and
 * navigation intact.
 */

interface Props {
  children: ReactNode;
  /** Shown in the fallback so an analyst knows which view failed. */
  label?: string;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Keep the stack in the console — this is the only diagnostic an analyst
    // can hand back when a specific sample breaks a view.
    console.error(`[ErrorBoundary${this.props.label ? ` · ${this.props.label}` : ''}]`, error, info.componentStack);
  }

  private reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div role="alert" className="max-w-2xl mx-auto my-12 bg-white border border-red-200 rounded-xl shadow-sm overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-3 bg-red-50 border-b border-red-200">
          <AlertOctagon className="h-4 w-4 text-red-600" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-red-800">
            {this.props.label ? `${this.props.label} failed to render` : 'Something went wrong'}
          </h2>
        </div>

        <div className="p-5 space-y-4">
          <p className="text-sm text-gray-600">
            This view could not be displayed. The rest of the application is unaffected —
            other views and the case history remain available.
          </p>

          <pre className="text-xs bg-gray-50 border border-gray-200 rounded-lg p-3 overflow-x-auto text-gray-700">
            {error.message || String(error)}
          </pre>

          <button
            onClick={this.reset}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Try again
          </button>
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;
