/**
 * Commercial license agreement text -- ported from ares-v3-landing (Ref).
 *
 * NOT a legal sign-off: the structure and most clauses are carried over
 * as a starting point, but section 2's original text named a specific
 * payment mechanism (x402/crypto, seat-based one-time purchase via pay.sh)
 * that does not match this app's actual billing model (`plans` table,
 * subscription tiers -- see docs/BIZ-2-licensing-tiers.md). That paragraph
 * and the reference's "Proceed to checkout" CTA (pointing at a page this
 * app doesn't have) were removed rather than left pointing at something
 * wrong. This needs real legal/business review before it's treated as
 * this product's actual binding terms.
 */
export function LicenseAgreementArticle() {
  return (
    <>
      <header className="mb-10 border-b border-border pb-8">
        <p className="mb-2 text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground">ARES Auditor</p>
        <h1 className="text-3xl font-medium tracking-tight text-foreground sm:text-4xl">
          Commercial license agreement
        </h1>
        <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
          This agreement applies only to the optional paid commercial license for ARES. The public source code on GitHub
          is licensed separately under the repository licenses (MIT and Apache-2.0 as stated there).
          &quot;Licensee&quot; means the company or individual that pays; &quot;Authorized User&quot; means the one
          named individual assigned to that purchase (one seat = one person).
        </p>
      </header>

      <div className="space-y-10 text-sm leading-relaxed text-foreground/90">
        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">1. Parties</h2>
          <p>
            This agreement is between the party that completes the purchase (&quot;Licensee&quot;) and the licensors of
            the ARES project (&quot;Licensor&quot;), including maintainers and contributors who offer the optional
            commercial license. If Licensee is a company, the company&mdash;not each employee&mdash;is the contracting
            party unless a separate team agreement says otherwise. Licensor is not a law firm; consult counsel if you
            need legal advice.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">2. Open source vs. commercial license</h2>
          <p>
            The ARES engine and related materials published as open source remain available under the terms of the
            applicable open-source licenses in the repository. Nothing in this agreement restricts Licensee&apos;s
            rights under those licenses for the corresponding code.
          </p>
          <p>
            The commercial license is separate from the open-source grants: it covers a defined number of{' '}
            <strong>seats</strong> (each seat is tied to one <strong>Authorized User</strong>&mdash;a single named
            developer), billed per your selected plan.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">3. Grant</h2>
          <p>
            Subject to full payment and compliance with this agreement, Licensor grants Licensee a non-exclusive,
            non-transferable right for each purchased seat, exercised only by the corresponding{' '}
            <strong>Authorized User</strong>, to use the ARES materials covered by the commercial offer for
            Licensee&apos;s internal engineering work and for building and operating products and services for Licensee
            and Licensee&apos;s clients, within the scope described at purchase.
          </p>
          <h3 className="mt-4 text-base font-medium text-foreground/90">3.1 Seats: solo developer vs. team</h3>
          <ul className="list-disc space-y-2 pl-5 marker:text-muted-foreground">
            <li>
              <strong>One seat (default offer):</strong> exactly one Authorized User at a time. That person may be a
              solo founder purchasing in their own name, or an employee or contractor whom Licensee designates in
              writing or in the purchase record. The same person may work across multiple machines and repos for
              Licensee; the seat is not shared across different people.
            </li>
            <li>
              <strong>Multiple developers:</strong> each additional person who needs commercial entitlements must be
              covered by an additional seat unless Licensor and Licensee have signed a separate volume or team agreement
              that lists covered headcount or a site-wide license.
            </li>
            <li>
              <strong>Reassignment:</strong> Licensee may replace the Authorized User for a seat occasionally (for
              example when someone leaves the team) by notifying Licensor through the same support contact used for
              account support, unless a separate process is published. Frequent rotation to circumvent seat limits is
              not permitted.
            </li>
          </ul>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">4. Permitted use</h2>
          <ul className="list-disc space-y-2 pl-5 marker:text-muted-foreground">
            <li>
              Each <strong>Authorized User</strong> may use, modify, and integrate ARES for Licensee under the
              open-source licenses for public portions, and under this agreement for commercial entitlements tied to
              their seat.
            </li>
            <li>
              Run scans, CI integrations, and optional server or IDE workflows as documented, on behalf of Licensee
              only.
            </li>
          </ul>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">5. Restrictions</h2>
          <p>Licensee must not:</p>
          <ul className="list-disc space-y-2 pl-5 marker:text-muted-foreground">
            <li>
              Repackage or redistribute the paid commercial materials (if any are provided separately from the public
              repo) as a standalone product competing with Licensor&apos;s commercial offering, without written
              permission.
            </li>
            <li>
              Remove or obscure copyright, license, or attribution notices required by the applicable open-source
              licenses.
            </li>
            <li>Misrepresent affiliation with Licensor or imply endorsement where none exists.</li>
          </ul>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">6. Ownership</h2>
          <p>
            Open-source components remain under their respective licenses. As between the parties, any separately
            provided commercial materials, branding, or documentation marked as proprietary remain the property of
            Licensor or its licensors. This agreement is a license, not a sale of all intellectual property rights.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">7. Payment and records</h2>
          <p>
            Payment is processed as described on your billing page at the time of purchase. Licensee should retain
            payment records as proof of purchase and, where practical, note which Authorized User each seat is assigned
            to. Licensor may rely on those records to validate entitlement.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">8. Updates and support</h2>
          <p>
            Where marketing copy refers to &quot;lifetime&quot; access, it means access to updates and materials made
            available under the commercial offer for the ARES product line for the lifetime of that offering, at
            Licensor&apos;s discretion. There is no guaranteed response time, service level, or feature roadmap unless
            expressly agreed in writing.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">9. Disclaimer</h2>
          <p>
            The software and materials are provided &quot;as is&quot;. Licensor disclaims warranties to the fullest
            extent permitted by law, including implied warranties of merchantability, fitness for a particular purpose,
            and non-infringement. ARES is a security-oriented tool; results depend on configuration and inputs. Licensee
            is responsible for how it is used and for compliance with applicable laws and policies.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">10. Limitation of liability</h2>
          <p>
            To the maximum extent permitted by law, Licensor will not be liable for indirect, incidental, special,
            consequential, or punitive damages, or for loss of profits, data, or goodwill. Licensor&apos;s aggregate
            liability arising from this agreement will not exceed the amount Licensee paid for the commercial license
            giving rise to the claim.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">11. Term and termination</h2>
          <p>
            This agreement begins when Licensee completes a qualifying purchase or when an Authorized User first
            exercises commercial entitlements, whichever is earlier. Licensor may suspend or terminate rights if
            Licensee or an Authorized User materially breaches this agreement. Provisions that by their nature should
            survive will survive termination.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">12. Changes</h2>
          <p>
            Licensor may update this page to clarify terms or reflect product changes. Material changes will be
            indicated by an updated effective date. Continued use of commercial entitlements after changes constitutes
            acceptance where permitted by law.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">13. Governing law</h2>
          <p>
            Unless mandatory local law provides otherwise, this agreement is governed by the laws applicable to the
            contracting entity offering the license, without regard to conflict-of-law rules. Courts in that
            jurisdiction have exclusive venue, subject to mandatory consumer protections where they apply.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-medium text-foreground">14. Contact</h2>
          <p>
            For questions about this agreement or the commercial license, contact the project maintainers via the public
            channels linked from this site.
          </p>
        </section>

        <p className="border-t border-border pt-8 text-xs text-muted-foreground">
          By purchasing or using the paid commercial license, you acknowledge that you have read this agreement.
        </p>
      </div>
    </>
  )
}
