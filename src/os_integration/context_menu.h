// context_menu.h — Windows shell integration (right-click context menu)
// Registry-based static verbs under HKCU — no admin rights required.
#pragma once
#include <string>

namespace wrc {
namespace shell {

bool isIntegrated();
bool integrate();     // adds "Add to WRC archive…" + "Extract with WRC…"
bool unintegrate();
std::wstring exePath();  // path of the running executable

}  // namespace shell
}  // namespace wrc
