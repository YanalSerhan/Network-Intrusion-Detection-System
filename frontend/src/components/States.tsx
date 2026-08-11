/**
 * Loading, error and empty states.
 *
 * Shared so every panel fails the same way. `role="status"` announces loading
 * politely; `role="alert"` interrupts, which is right for an error but wrong
 * for a spinner that resolves on its own.
 */
import styles from "./States.module.css";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <p className={styles.state} role="status">
      {label}…
    </p>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className={styles.state} role="alert">
      <p className={styles.errorText}>{message}</p>
      {onRetry && (
        <button type="button" className={styles.retry} onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ message }: { message: string }) {
  return <p className={styles.state}>{message}</p>;
}
