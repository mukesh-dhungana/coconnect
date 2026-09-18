<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{ csrf_token() }}">
<title>Access Control · Co Connect</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Quicksand:wght@600;700&family=Hanken+Grotesk:wght@400;500;600&display=swap">
<style>
  body { font-family: "Hanken Grotesk", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
  h1 { font-family: "Quicksand", "Hanken Grotesk", ui-sans-serif, system-ui, sans-serif; }
  .chip { @apply inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium; }
</style>
</head>
<body class="bg-slate-100 text-slate-800">

<header class="bg-[#04205a] text-white">
  <div class="mx-auto max-w-7xl px-6 py-5 flex items-center justify-between flex-wrap gap-4">
    <div class="flex items-center gap-3">
      <img src="/brand/cc-app-icon.png" alt="" width="512" height="512" class="h-9 w-9 rounded-[22%]">
      <div>
        <h1 class="text-xl font-semibold tracking-tight">Access control</h1>
        <p class="text-sm text-[#8fc1f6]">Dynamic modules · roles · permissions · multi-role users</p>
      </div>
    </div>
    <form method="GET" class="flex items-center gap-2">
      <label class="text-sm text-[#8fc1f6]">Account</label>
      <select name="account" onchange="this.form.submit()"
              class="rounded bg-white/10 border border-white/20 px-3 py-1.5 text-sm text-white">
        @foreach ($accounts as $a)
          <option value="{{ $a->id }}" @selected($a->id === $account->id) class="text-slate-800">{{ $a->name }}</option>
        @endforeach
      </select>
    </form>
  </div>
</header>

@if (session('status') || session('error'))
  <div class="mx-auto max-w-7xl px-6 pt-4">
    <div class="rounded border px-4 py-2 text-sm {{ session('error') ? 'border-red-300 bg-red-50 text-red-800' : 'border-emerald-300 bg-emerald-50 text-emerald-800' }}">
      {{ session('error') ?? session('status') }}
    </div>
  </div>
@endif

<main class="mx-auto max-w-7xl px-6 py-6 space-y-6">

  {{-- Modules --}}
  <section class="rounded-lg bg-white shadow-sm ring-1 ring-slate-200">
    <div class="border-b border-slate-200 px-5 py-3 flex items-baseline justify-between">
      <h2 class="font-semibold">Modules</h2>
      <p class="text-xs text-slate-500">Modules are rows, not code. Toggling one changes what
        <strong>{{ $account->name }}</strong> can access — immediately, for every user.</p>
    </div>
    <div class="grid gap-3 p-5 sm:grid-cols-2 lg:grid-cols-4">
      @foreach ($modules as $m)
        <div class="rounded border p-3 {{ $m->is_enabled ? 'border-emerald-300 bg-emerald-50/50' : 'border-slate-200 bg-slate-50' }}">
          <div class="flex items-start justify-between gap-2">
            <div>
              <div class="font-medium text-sm">{{ $m->model->name }}</div>
              <code class="text-[11px] text-slate-500">{{ $m->model->key }}</code>
            </div>
            @if ($m->model->is_core)
              <span class="rounded bg-slate-200 px-1.5 py-0.5 text-[11px] font-medium text-slate-600">core</span>
            @endif
          </div>
          <div class="mt-2 flex items-center justify-between">
            <span class="text-[11px] {{ $m->is_enabled ? 'text-emerald-700' : 'text-slate-500' }}">
              {{ $m->is_enabled ? 'Enabled' : 'Disabled' }}
            </span>
            @unless ($m->model->is_core)
              <form method="POST" action="{{ route('demo.toggle', [$account, $m->model]) }}">
                @csrf
                <button class="rounded px-2 py-0.5 text-[11px] font-medium ring-1
                  {{ $m->is_enabled ? 'text-red-700 ring-red-300 hover:bg-red-50' : 'text-emerald-700 ring-emerald-300 hover:bg-emerald-50' }}">
                  {{ $m->is_enabled ? 'Disable' : 'Enable' }}
                </button>
              </form>
            @endunless
          </div>
        </div>
      @endforeach
    </div>
  </section>

  {{-- Live permission check --}}
  <section class="rounded-lg bg-white shadow-sm ring-1 ring-slate-200">
    <div class="border-b border-slate-200 px-5 py-3">
      <h2 class="font-semibold">Permission check</h2>
      <p class="text-xs text-slate-500">The question the module exists to answer: may this person do this, here?</p>
    </div>
    <div class="p-5">
      <div class="grid gap-3 sm:grid-cols-5">
        <select id="c-user" class="rounded border-slate-300 text-sm">
          @foreach ($matrix as $row)
            <option value="{{ $row->user->id }}">{{ $row->user->name }}</option>
          @endforeach
        </select>
        <select id="c-perm" class="rounded border-slate-300 text-sm sm:col-span-2">
          @foreach ($roles->pluck('permissions')->flatten()->unique('id')->sortBy('name') as $p)
            <option value="{{ $p->name }}">{{ $p->name }}</option>
          @endforeach
        </select>
        <select id="c-loc" class="rounded border-slate-300 text-sm">
          <option value="">— account level —</option>
          @foreach ($account->locations as $l)
            <option value="{{ $l->id }}">{{ $l->name }}</option>
          @endforeach
        </select>
        <button id="c-go" class="rounded bg-[#0b2447] px-4 py-2 text-sm font-medium text-white hover:bg-[#123a6b]">Check</button>
      </div>
      <div id="c-result" class="mt-4 hidden rounded px-4 py-3 text-sm font-medium"></div>
    </div>
  </section>

  {{-- Users --}}
  <section class="rounded-lg bg-white shadow-sm ring-1 ring-slate-200">
    <div class="border-b border-slate-200 px-5 py-3">
      <h2 class="font-semibold">Users and the roles they hold</h2>
      <p class="text-xs text-slate-500">One user may hold several roles at different scopes. Permissions are the union.</p>
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="bg-slate-50 text-left text-xs uppercase text-slate-500">
          <tr>
            <th class="px-5 py-2">User</th>
            <th class="px-5 py-2">Roles held</th>
            <th class="px-5 py-2">Perms</th>
            <th class="px-5 py-2">Visible modules in {{ $account->name }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
        @foreach ($matrix as $row)
          <tr>
            <td class="px-5 py-3 align-top">
              <div class="font-medium">{{ $row->user->name }}</div>
              <div class="text-xs text-slate-500">{{ $row->user->email }}</div>
            </td>
            <td class="px-5 py-3 align-top">
              <div class="space-y-1">
              @forelse ($row->assignments as $a)
                @php
                  $tone = match ($a->status) {
                    'active'    => 'bg-emerald-100 text-emerald-800',
                    'temporary' => 'bg-amber-100 text-amber-800',
                    'expired'   => 'bg-slate-200 text-slate-500 line-through',
                    'revoked'   => 'bg-red-100 text-red-700 line-through',
                    default     => 'bg-slate-100 text-slate-600',
                  };
                @endphp
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="rounded px-1.5 py-0.5 text-[11px] font-medium {{ $tone }}">{{ $a->role->name }}</span>
                  <span class="text-[11px] text-slate-500">
                    {{ $a->scope_level }}@if ($a->location) · {{ $a->location->name }}@elseif ($a->account) · {{ $a->account->name }}@endif
                  </span>
                  @if ($a->status === 'temporary')
                    <span class="text-[11px] text-amber-700">expires {{ $a->valid_until->diffForHumans() }}</span>
                  @elseif ($a->status === 'expired')
                    <span class="text-[11px] text-slate-400">expired</span>
                  @endif
                </div>
              @empty
                <span class="text-xs text-slate-400">No roles</span>
              @endforelse
              </div>
            </td>
            <td class="px-5 py-3 align-top tabular-nums">{{ $row->permCount }}</td>
            <td class="px-5 py-3 align-top">
              @forelse ($row->modules as $mk)
                <span class="mr-1 inline-block rounded bg-blue-50 px-1.5 py-0.5 text-[11px] text-blue-800">{{ $mk }}</span>
              @empty
                <span class="text-xs text-slate-400">none</span>
              @endforelse
            </td>
          </tr>
        @endforeach
        </tbody>
      </table>
    </div>
  </section>

  {{-- Roles --}}
  <section class="rounded-lg bg-white shadow-sm ring-1 ring-slate-200">
    <div class="border-b border-slate-200 px-5 py-3">
      <h2 class="font-semibold">Roles</h2>
      <p class="text-xs text-slate-500">Scope decides where a role can be granted. High-risk permissions are marked.
        Permissions struck through belong to a module <strong>{{ $account->name }}</strong> has not enabled &mdash;
        the role still carries them, they just resolve to <em>deny</em> here.</p>
    </div>
    <div class="divide-y divide-slate-100">
      @foreach ($roles as $role)
        <div class="px-5 py-3">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="font-medium text-sm">{{ $role->name }}</span>
            <span class="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">{{ $role->scope_level }}</span>
            @if ($role->is_system)
              <span class="rounded bg-indigo-50 px-1.5 py-0.5 text-[11px] text-indigo-700">system</span>
            @endif
            @php
              $inert = $role->permissions->filter(fn ($p) => in_array($p->module->key, $disabledModuleKeys, true));
            @endphp
            <span class="text-[11px] text-slate-400">{{ $role->permissions->count() }} permissions</span>
            @if ($inert->isNotEmpty())
              <span class="rounded bg-amber-50 px-1.5 py-0.5 text-[11px] text-amber-800 ring-1 ring-amber-200">
                {{ $inert->count() }} inactive in {{ $account->name }}
              </span>
            @endif
          </div>
          <div class="mt-1.5 flex flex-wrap gap-1">
            @foreach ($role->permissions->sortBy('name') as $p)
              @php $off = in_array($p->module->key, $disabledModuleKeys, true); @endphp
              <span class="rounded px-1.5 py-0.5 text-[11px]
                    @if ($off) bg-slate-100 text-slate-400 line-through decoration-slate-400
                    @elseif ($p->is_high_risk) bg-red-50 text-red-700 ring-1 ring-red-200
                    @else bg-slate-50 text-slate-600 @endif"
                    title="{{ $off ? $p->module->name.' is not enabled for '.$account->name.' — this permission denies here.' : $p->description }}">{{ $p->name }}</span>
            @endforeach
          </div>
        </div>
      @endforeach
    </div>
  </section>
</main>

<script>
document.getElementById('c-go').addEventListener('click', async () => {
  const box = document.getElementById('c-result');
  const res = await fetch('{{ route('demo.check') }}', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': document.querySelector('meta[name=csrf-token]').content,
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      user_id: document.getElementById('c-user').value,
      permission: document.getElementById('c-perm').value,
      account_id: {{ $account->id }},
      location_id: document.getElementById('c-loc').value || null,
    }),
  });
  const data = await res.json();
  const user = document.getElementById('c-user').selectedOptions[0].text;
  const perm = document.getElementById('c-perm').value;
  const loc  = document.getElementById('c-loc').selectedOptions[0].text;
  box.className = 'mt-4 rounded px-4 py-3 text-sm font-medium ' +
    (data.allowed ? 'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-200'
                  : 'bg-red-50 text-red-800 ring-1 ring-red-200');
  box.textContent = `${data.allowed ? 'ALLOWED' : 'DENIED'} — ${user} · ${perm} · ${loc}`;
  box.classList.remove('hidden');
});
</script>

<footer class="mx-auto max-w-7xl px-6 pb-10 pt-6">
  <p class="text-xs text-slate-500">&copy; {{ date('Y') }} Co Connect &middot; Informed. Engaged. Safe. Connected.</p>
</footer>
</body>
</html>
