"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabase/client";

export function TodoList() {
  const [todos, setTodos] = useState<{ id: number; title: string }[]>([]);
  useEffect(() => {
    supabase.from("todos").select("id,title").then(({ data }) => setTodos(data ?? []));
  }, []);
  return <ul>{todos.map((t) => <li key={t.id}>{t.title}</li>)}</ul>;
}
