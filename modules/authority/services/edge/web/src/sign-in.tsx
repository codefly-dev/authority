import type { ReactNode } from "react";
import {
	Avatar,
	AvatarFallback,
	Badge,
	Banner,
	Button,
	Card,
	EmptyState,
	ErrorState,
	List,
	ListItem,
} from "@codefly-dev/ui/layout";

/** One person the authority's fixture defines, as the edge renders them. */
export interface Person {
	description?: string;
	startHere?: boolean;
	personId: string;
	email: string;
	organizationId: string;
	organizationName?: string;
	roles: string[];
	fixtureToken: string;
}

/**
 * Who the browser already is (code/actas.go): the session it holds, the team
 * it is cast onto if any, whether the way back is held, and the organisation's
 * teams it may ask to act as. The authority decides each ask.
 */
export interface Session {
	personId: string;
	personDisplayName: string;
	organizationId: string;
	organizationDisplayName: string;
	roles: string[];
	teamIds: string[];
	castTeamId?: string;
	back?: boolean;
	teams: string[];
}

/** What the edge writes into the page: who may sign in and where to return. */
export interface SignInData {
	people: Person[];
	return: string;
	session?: Session;
	refused?: string;
}

/** The island's id, shared with the edge's template (code/signin.go). */
export const DATA_ISLAND = "sign-in";

// readSignInData reads what the edge rendered into the page. A page served any
// other way (a dev server, a stale build) has no data, which is said rather
// than shown as an empty list.
export function readSignInData(doc: Document): SignInData | Error {
	const island = doc.getElementById(DATA_ISLAND);
	if (!island?.textContent) {
		return new Error("the page carries no sign-in data: the edge did not serve it");
	}
	try {
		const parsed: unknown = JSON.parse(island.textContent);
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!Array.isArray((parsed as { people?: unknown }).people) ||
			typeof (parsed as { return?: unknown }).return !== "string"
		) {
			return new Error("the page's sign-in data has no people or no return path");
		}
		return parsed as SignInData;
	} catch (err) {
		return new Error(
			`the page's sign-in data is not JSON: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
}

// initials is the mark on a person's avatar: the first letters of the words
// before the @ of their email, at most two.
function initials(email: string): string {
	const local = email.split("@")[0] ?? "";
	const letters = local
		.split(/[._+-]+/)
		.filter(Boolean)
		.map((word) => word[0]?.toUpperCase() ?? "")
		.join("");
	return letters.slice(0, 2) || "?";
}

// A plain form posted to /auth/act-as: the browser becomes the team, or comes
// back, with no script between the click and the session.
function ActAsForm({ fields, back, children }: { fields: Record<string, string>; back: string; children: ReactNode }) {
	return (
		<form method="post" action="/auth/act-as">
			{Object.entries(fields).map(([name, value]) => (
				<input key={name} type="hidden" name={name} value={value} />
			))}
			<input type="hidden" name="return" value={back} />
			{children}
		</form>
	);
}

// ActAs is the card for a browser that holds a session: who it is, and the
// organisation's teams it may ask to act as. A cast session is said, with
// the way back; the authority's refusal of the last ask is shown by name.
function ActAs({ session, back, refused }: { session: Session; back: string; refused?: string }) {
	const cast = session.castTeamId;
	return (
		<Card
			title={cast ? `Acting as team ${cast}` : `Signed in as ${session.personDisplayName}`}
			description={
				cast
					? `${session.personDisplayName} · ${session.organizationDisplayName || session.organizationId}. This session is the team and nothing else: none of your own roles, no other team.`
					: `${session.organizationDisplayName || session.organizationId}. Act as a team to see exactly what its members see; the authority decides which teams you may be.`
			}
		>
			{refused && <Banner tone="danger" title={`The authority refused: ${refused}`} />}
			{cast ? (
				<ActAsForm fields={{ action: "back" }} back={back}>
					<Button type="submit" size="sm" disabled={!session.back}>
						Back to your own session
					</Button>
				</ActAsForm>
			) : (
				<>
					<p style={{ display: "inline-flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
						{session.roles.length === 0 ? (
							<Badge tone="neutral">no organisation role</Badge>
						) : (
							session.roles.map((role) => (
								<Badge key={role} variant="secondary">
									{role}
								</Badge>
							))
						)}
						{session.teamIds.map((team) => (
							<Badge key={team} tone="info">
								member of {team}
							</Badge>
						))}
					</p>
					{session.teams.length === 0 ? (
						<p>No team of {session.organizationDisplayName || session.organizationId} is seated yet: a role-gated target seats one per role once it is composed.</p>
					) : (
						<List variant="divided" label="Teams to act as">
							{session.teams.map((team) => (
								<ListItem
									key={team}
									actions={
										<ActAsForm fields={{ team }} back={back}>
											<Button type="submit" size="sm" variant="outline">
												Act as this team
											</Button>
										</ActAsForm>
									}
								>
									{team}
								</ListItem>
							))}
						</List>
					)}
				</>
			)}
		</Card>
	);
}

export function SignIn({ data }: { data: SignInData | Error }) {
	const session = data instanceof Error ? undefined : data.session;
	return (
		<main style={{ maxWidth: 560, margin: "0 auto", padding: "48px 16px", display: "grid", gap: 20 }}>
			{session && !(data instanceof Error) && <ActAs session={session} back={data.return} refused={data.refused} />}
			<Card
				title={session ? "Switch person" : "Sign in"}
				description="This run's authority signs in the people of its fixture. Choose who you are."
			>
				{data instanceof Error ? (
					<ErrorState title="Nobody can be signed in from this page" detail={data.message} />
				) : data.people.length === 0 ? (
					<EmptyState
						heading="No fixture people"
						description="This authority lists no fixture people: it signs people in through its own identity provider."
					/>
				) : (
					<List variant="divided" label="People who may sign in">
						{data.people.map((person) => (
							<ListItem
								key={person.fixtureToken}
								icon={
									<Avatar>
										<AvatarFallback>{initials(person.email)}</AvatarFallback>
									</Avatar>
								}
								description={person.description ? undefined : (
									<span style={{ display: "inline-flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
										{person.organizationId && (
											<span title={person.organizationId}>{person.organizationName || person.organizationId}</span>
										)}
										{person.roles.length === 0 ? (
											<Badge tone="neutral">no role</Badge>
										) : (
											person.roles.map((role) => (
												<Badge key={role} variant="secondary">
													{role}
												</Badge>
											))
										)}
									</span>
								)}
								actions={
									// A plain form: the browser posts the choice back to the edge,
									// which signs the person in and returns them, with no script
									// between the click and the session.
									<form method="post" action="/auth/sign-in">
										<input type="hidden" name="fixtureToken" value={person.fixtureToken} />
										<input type="hidden" name="return" value={data.return} />
										<Button type="submit" size="sm">
											Sign in
										</Button>
									</form>
								}
							>
								{person.description || person.email}
								{person.startHere && <Badge tone="neutral">Start here</Badge>}
							</ListItem>
						))}
					</List>
				)}
			</Card>
		</main>
	);
}
