import type { ReactNode } from "react";
import {
	Badge,
	Banner,
	Button,
	Card,
	EmptyState,
	Field,
	List,
	ListItem,
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@codefly-dev/ui/layout";

// What the edge writes into the page at /auth/setup (code/setup.go): the
// authority's answers as their protojson, read with the person's session.
// The page decides nothing; each change is a form the edge posts back.
type Scope = { resourceKind: string; actions: string[]; attachedOnly: boolean; resourceIds: string[] };
type Tool = { name: string; binding: string; write: boolean };
type Capability = { module: string; operation: string; requires: Scope[]; tools: Tool[] };
type Role = { name: string; scopes: Scope[]; capabilities: Capability[] };
type Installation = { id: string; target: string; status: string; revision: string; role: string };
type Review = {
	target: string;
	approval: { targetId: string; generation: string; expectedRevision: string; digest: string };
	roles: Role[];
	ceiling: { binding: string; module: string; scopes: Scope[] }[];
	installation?: Installation;
	toolsComposed: boolean;
};
export interface SetupData {
	organizationId: string;
	personId: string;
	people: { id: string; email: string }[];
	teams: string[];
	offers?: { offers: { target: string; generation: string }[] };
	installations?: { installations: Installation[] };
	review?: Review;
	grants?: { grants: { role: string; personId: string; teamId: string }[] };
	operationId: string;
	retry?: Record<string, string>;
	notice?: string;
	error?: string;
}

const statusWords: Record<string, string> = {
	STATUS_ACTIVE: "Installed",
	STATUS_PENDING: "Pending",
	STATUS_REVOKED: "Uninstalled",
};

function scopeText(s: Scope, confined: boolean): string {
	if (!confined) {
		return `${s.resourceKind}: ${s.actions.join(", ")}`;
	}
	const reach = s.attachedOnly
		? s.resourceIds.length
			? `only ${s.resourceIds.join(", ")}`
			: "only resources attached to the installation (none yet)"
		: "what this installation owns";
	return `${s.resourceKind}: ${s.actions.join(", ")} · ${reach}`;
}

const wrap = { display: "inline-flex", flexWrap: "wrap", gap: 6 } as const;
const link = { textDecoration: "underline", textUnderlineOffset: 3 } as const;

// Scopes is what a role or binding names; a role's are confined to the
// installation, which each says.
function Scopes({ scopes, confined = true }: { scopes: Scope[]; confined?: boolean }) {
	return (
		<span style={wrap}>
			{scopes.map((s) => (
				<Badge key={s.resourceKind + s.actions.join()} variant="secondary">
					{scopeText(s, confined)}
				</Badge>
			))}
		</span>
	);
}

// A plain form posted to the edge; hidden values are what the authority returned.
function Change({ fields, children }: { fields: Record<string, string>; children: ReactNode }) {
	return (
		<form method="post" action="/auth/setup" style={{ display: "grid", gap: 12 }}>
			{Object.entries(fields).map(([name, value]) => (
				<input key={name} type="hidden" name={name} value={value} />
			))}
			{children}
		</form>
	);
}

function RoleCard({ role }: { role: Role }) {
	return (
		<Card title={`Role: ${role.name}`} description={<Scopes scopes={role.scopes} />}>
			{role.capabilities.length === 0 ? (
				<p>No composed operation is covered by this role.</p>
			) : (
				<Table>
					<TableHeader>
						<TableRow>
							<TableHead>Module</TableHead>
							<TableHead>Operation</TableHead>
							<TableHead>Requires</TableHead>
							<TableHead>Robin tools</TableHead>
						</TableRow>
					</TableHeader>
					<TableBody>
						{role.capabilities.map((c) => (
							<TableRow key={c.module + c.operation}>
								<TableCell>{c.module}</TableCell>
								<TableCell style={{ whiteSpace: "normal", wordBreak: "break-word" }}>
									<code>{c.operation}</code>
								</TableCell>
								<TableCell style={{ whiteSpace: "normal" }}>
									<Scopes scopes={c.requires} confined={false} />
								</TableCell>
								<TableCell style={{ whiteSpace: "normal" }}>
									{c.tools.length === 0 ? (
										"Not exposed as a tool"
									) : (
										<span style={wrap}>
											{c.tools.map((t) => (
												<Badge key={t.binding} tone={t.write ? "warning" : "info"} title={t.binding}>
													{t.name}
													{t.write ? " · changes data" : ""}
												</Badge>
											))}
										</span>
									)}
								</TableCell>
							</TableRow>
						))}
					</TableBody>
				</Table>
			)}
		</Card>
	);
}

function Install({ data, review }: { data: SetupData; review: Review }) {
	// A retry resubmits exactly what the authority did not confirm.
	const retry = data.retry;
	const fields = retry ?? {
		action: "install",
		target: review.target,
		targetId: review.approval.targetId,
		generation: review.approval.generation,
		expectedRevision: review.approval.expectedRevision,
		digest: review.approval.digest,
		operationId: data.operationId,
	};
	return (
		<Card
			title={`Install ${review.target}`}
			description={`Generation ${review.approval.generation}. Your consent applies to this exact reviewed version; if it changes before you install, the authority refuses and you review again.`}
		>
			<Change fields={retry ? Object.fromEntries(Object.entries(retry).filter(([k]) => k !== "role" && k !== "consent")) : fields}>
				<Field label="Agent role" description="The role the solution's own agent holds on what this installation owns. Choose the least it needs.">
					{(control) => (
						<select {...control} name="role" required defaultValue={retry?.role ?? ""}>
							<option value="" disabled>
								Choose a role…
							</option>
							{review.roles.map((r) => (
								<option key={r.name} value={r.name}>
									{r.name}
								</option>
							))}
						</select>
					)}
				</Field>
				<label style={{ display: "flex", gap: 8, alignItems: "center" }}>
					<input type="checkbox" name="consent" required defaultChecked={retry?.consent === "on"} />I consent to this version, its roles and
					its permission ceiling.
				</label>
				<div>
					<Button type="submit">{retry ? `Retry install of ${review.target}` : `Install ${review.target}`}</Button>
				</div>
			</Change>
		</Card>
	);
}

function Grants({ data, review, installation }: { data: SetupData; review: Review; installation: Installation }) {
	const grants = data.grants?.grants ?? [];
	const who = (g: { personId: string; teamId: string }) =>
		g.personId ? (data.people.find((p) => p.id === g.personId)?.email ?? g.personId) : `Team ${g.teamId}`;
	const base = { target: review.target, installationId: installation.id };
	return (
		<Card
			title="Who may reach it?"
			description={`${statusWords[installation.status] ?? installation.status} · agent role ${installation.role} · revision ${installation.revision}. A role granted here gives its holder the capabilities and tools above, on this installation only.`}
		>
			<Change fields={{ ...base, action: "grant" }}>
				<Field label="Role">
					{(control) => (
						<select {...control} name="role" required defaultValue="">
							<option value="" disabled>
								Choose a role…
							</option>
							{review.roles.map((r) => (
								<option key={r.name}>{r.name}</option>
							))}
						</select>
					)}
				</Field>
				<Field label="Person or team">
					{(control) => (
						<select {...control} name="subject" required defaultValue="">
							<option value="" disabled>
								Choose a person or team…
							</option>
							{data.people.map((p) => (
								<option key={p.id} value={`person:${p.id}`}>
									{p.email}
								</option>
							))}
							{data.teams.map((t) => (
								<option key={t} value={`team:${t}`}>
									Team {t}
								</option>
							))}
						</select>
					)}
				</Field>
				<div>
					<Button type="submit" disabled={installation.status !== "STATUS_ACTIVE"}>
						Grant role
					</Button>
				</div>
			</Change>
			{grants.length === 0 ? (
				<p>No person or team holds a role on this installation yet.</p>
			) : (
				<List variant="divided" label="Role grants">
					{grants.map((g) => (
						<ListItem
							key={g.role + g.personId + g.teamId}
							actions={
								<Change fields={{ ...base, action: "revoke", role: g.role, subject: g.personId ? `person:${g.personId}` : `team:${g.teamId}` }}>
									<Button type="submit" size="sm" variant="outline">
										Remove {who(g)}
									</Button>
								</Change>
							}
						>
							{g.role} · {who(g)}
						</ListItem>
					))}
				</List>
			)}
		</Card>
	);
}

export function Setup({ data }: { data: SetupData }) {
	const offers = data.offers?.offers ?? [];
	const installed = new Map((data.installations?.installations ?? []).map((i) => [i.target, i]));
	const review = data.review;
	return (
		<main style={{ maxWidth: 1080, margin: "0 auto", padding: "32px 16px", display: "grid", gap: 20 }}>
			<Card
				title="Modules & solutions"
				description={`Install solutions for ${data.organizationId} and grant their roles. Installing a solution and granting a role gives that person or team its capabilities, and Robin the matching tools; an agent declares which of those tools it uses. The authority checks current grants on every call.`}
				actions={
					<a style={link} href="/auth/sign-in?return=%2Fauth%2Fsetup">
						Switch person
					</a>
				}
			>
				{data.notice && <Banner tone="success" title={data.notice} />}
				{data.error && <Banner tone="danger" title={data.error} />}
				{data.offers && offers.length === 0 ? (
					<EmptyState
						heading="No solution is available"
						description="This run delivered no solution. Modules are installed by the composition and are not listed here."
					/>
				) : (
					offers.length > 0 && (
						<Table aria-label="Available modules and solutions">
							<TableHeader>
								<TableRow>
									<TableHead>Solution</TableHead>
									<TableHead>Generation</TableHead>
									<TableHead>State</TableHead>
									<TableHead>Action</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{offers.map((o) => {
									const inst = installed.get(o.target);
									return (
										<TableRow key={o.target}>
											<TableCell>{o.target}</TableCell>
											<TableCell>{o.generation}</TableCell>
											<TableCell>
												<Badge tone={inst?.status === "STATUS_ACTIVE" ? "success" : "neutral"}>
													{inst ? (statusWords[inst.status] ?? inst.status) : "Not installed"}
												</Badge>
											</TableCell>
											<TableCell>
												<a style={link} href={`/auth/setup?target=${encodeURIComponent(o.target)}`}>
													{inst ? "Review and grant roles" : "Review and install"}
												</a>
											</TableCell>
										</TableRow>
									);
								})}
							</TableBody>
						</Table>
					)
				)}
			</Card>
			{review && (
				<>
					<Card
						title={`Review ${review.target}`}
						description="What each role grants, limited to what this installation owns, and the Robin tools those capabilities become. Tools are the composed operations' tool exposures; Robin and the authority check them again at every run."
					>
						{!review.toolsComposed && <Banner tone="info" title="This run composes no tool bindings, so no tool is listed." />}
						<p>Permission ceiling: what the solution may ask of each module it calls.</p>
						{review.ceiling.length === 0 ? (
							<p>The solution calls no other module.</p>
						) : (
							<List variant="divided" label="Permission ceiling">
								{review.ceiling.map((c) => (
									<ListItem key={c.binding} description={<Scopes scopes={c.scopes} confined={false} />}>
										{c.module}
									</ListItem>
								))}
							</List>
						)}
					</Card>
					{review.roles.map((r) => (
						<RoleCard key={r.name} role={r} />
					))}
					{review.installation && review.installation.status !== "STATUS_REVOKED" ? (
						<Grants data={data} review={review} installation={review.installation} />
					) : (
						<Install data={data} review={review} />
					)}
				</>
			)}
		</main>
	);
}

/** The setup data the edge rendered, when this page is the setup page. */
export function readSetupData(island: unknown): SetupData | undefined {
	const setup = (island as { setup?: SetupData } | null)?.setup;
	return setup && typeof setup.organizationId === "string" ? setup : undefined;
}
