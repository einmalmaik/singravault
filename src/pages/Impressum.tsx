// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { Footer } from "@/components/landing/Footer";
import { Header } from "@/components/landing/Header";
import { DesktopSubpageFrame } from "@/components/layout/DesktopSubpageFrame";
import { SEO } from "@/components/SEO";
import { shouldShowWebsiteChrome } from "@/platform/appShell";

function ImpressumContent() {
  return (
    <div className="w-full max-w-2xl space-y-8">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Impressum</h1>
      </div>

      <div className="prose prose-invert max-w-none space-y-6 rounded-lg border border-border/50 bg-card p-8 shadow-sm">
        <section>
          <h2 className="mb-4 text-xl font-semibold text-primary">
            Angaben gemaess Paragraph 5 TMG
          </h2>
          <div className="space-y-2 text-muted-foreground">
            <p className="font-medium text-foreground">MDC Management</p>
            <p>Maik Haedrich</p>
            <p>Welserstrasse 3</p>
            <p>87463 Dietmannsried</p>
            <p>Deutschland</p>
          </div>
        </section>

        <section>
          <h2 className="mb-4 text-xl font-semibold text-primary">Kontakt</h2>
          <div className="space-y-2 text-muted-foreground">
            <p>
              <span className="font-medium text-foreground">E-Mail:</span>{" "}
              <a
                href="mailto:kontakt@mauntingstudios.de"
                className="transition-colors hover:text-primary"
              >
                kontakt@mauntingstudios.de
              </a>
            </p>
            <p className="mt-4 text-sm italic">
              Wir sind nicht bereit oder verpflichtet, an
              Streitbeilegungsverfahren vor einer
              Verbraucherschlichtungsstelle teilzunehmen.
            </p>
          </div>
        </section>

        <section>
          <h2 className="mb-4 text-xl font-semibold text-primary">
            Rechtsform
          </h2>
          <div className="space-y-2 text-muted-foreground">
            <p>Einzelunternehmer</p>
          </div>
        </section>
      </div>
    </div>
  );
}

const Impressum = () => {
  const showWebsiteChrome = shouldShowWebsiteChrome();

  return (
    <>
      <SEO
        title="Impressum"
        description="Impressum und rechtliche Angaben für Singra Vault."
        path="/impressum"
        keywords={["Impressum", "Kontakt", "Rechtliche Hinweise", "TMG"]}
      />

      {showWebsiteChrome ? (
        <div className="min-h-screen bg-background flex flex-col">
          <Header />
          <main className="flex flex-1 flex-col items-center px-4 py-32 sm:px-6 lg:px-8">
            <ImpressumContent />
          </main>
          <Footer />
        </div>
      ) : (
        <DesktopSubpageFrame
          title="Impressum"
          description="Kontakt und rechtliche Angaben zu Singra Vault."
        >
          <ImpressumContent />
        </DesktopSubpageFrame>
      )}
    </>
  );
};

export default Impressum;
