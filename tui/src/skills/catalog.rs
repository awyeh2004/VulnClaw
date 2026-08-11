#[derive(Clone, Debug)]
pub struct SkillNode {
    pub name: String,
    pub children: Vec<SkillNode>,
}

pub fn skill_tree() -> Vec<SkillNode> {
    vec![
        SkillNode {
            name: "Recon".into(),
            children: vec![
                leaf("subdomain"),
                leaf("port"),
                leaf("fingerprint"),
                leaf("vuln-intel"),
            ],
        },
        SkillNode {
            name: "Scan".into(),
            children: vec![leaf("port-sweep"), leaf("service"), leaf("web")],
        },
        SkillNode {
            name: "Exploit".into(),
            children: vec![leaf("verify"), leaf("payload"), leaf("post-exploit")],
        },
        SkillNode {
            name: "Report".into(),
            children: vec![leaf("findings"), leaf("chain"), leaf("pdf-export")],
        },
    ]
}

fn leaf(name: &str) -> SkillNode {
    SkillNode {
        name: name.into(),
        children: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::skill_tree;

    #[test]
    fn exposes_vulnclaw_workflow_as_parent_nodes() {
        let skills = skill_tree();

        assert_eq!(skills.len(), 4);
        assert_eq!(skills[0].name, "Recon");
        assert_eq!(skills[1].name, "Scan");
        assert_eq!(skills[2].name, "Exploit");
        assert_eq!(skills[3].name, "Report");
        for node in &skills {
            assert!(!node.children.is_empty());
        }
    }
}
