import { useToast } from "@/hooks/use-toast";
import { Toast, ToastClose, ToastDescription, ToastProvider, ToastTitle, ToastViewport } from "@/components/ui/toast";
import { Copy } from "lucide-react";
import type { ReactNode } from "react";

function toastText(value: ReactNode): string {
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value.map(toastText).filter(Boolean).join(" ");
  }

  return "";
}

function buildCopyText(title: ReactNode, description: ReactNode): string {
  return [toastText(title), toastText(description)].filter(Boolean).join("\n");
}

async function copyVisibleToastText(text: string) {
  if (!text || !navigator.clipboard) {
    return;
  }

  await navigator.clipboard.writeText(text);
}

export function Toaster() {
  const { toasts } = useToast();

  return (
    <ToastProvider>
      {toasts.map(function ({ id, title, description, action, ...props }) {
        const copyText = buildCopyText(title, description);

        return (
          <Toast key={id} {...props}>
            <div className="grid gap-1">
              {title && <ToastTitle>{title}</ToastTitle>}
              {description && <ToastDescription>{description}</ToastDescription>}
            </div>
            {action}
            {copyText && (
              <button
                type="button"
                className="absolute right-9 top-2 rounded-md p-1 text-foreground/50 opacity-0 transition-opacity hover:text-foreground focus:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring group-hover:opacity-100 group-[.destructive]:text-red-300 group-[.destructive]:hover:text-red-50 group-[.destructive]:focus:ring-red-400"
                aria-label="Fehlermeldung kopieren"
                title="Fehlermeldung kopieren"
                onClick={() => {
                  void copyVisibleToastText(copyText);
                }}
              >
                <Copy className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
            <ToastClose />
          </Toast>
        );
      })}
      <ToastViewport />
    </ToastProvider>
  );
}
