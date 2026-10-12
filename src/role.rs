use crate::AdmissionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationRequirement {
    Authenticated,
    Guest,
}

pub struct RoleRule<Role> {
    pub description: String,
    pub authentication: AuthenticationRequirement,
    pub role: Role,
}

pub struct RoleRules<Role> {
    rules: Vec<RoleRule<Role>>,
}

impl<Role> Default for RoleRules<Role> {
    fn default() -> Self {
        Self { rules: Vec::new() }
    }
}

impl<Role> RoleRules<Role> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, rule: RoleRule<Role>) -> Result<(), AdmissionError> {
        if self
            .rules
            .iter()
            .any(|existing| existing.description == rule.description)
        {
            return Err(AdmissionError::DuplicateRole(rule.description));
        }
        self.rules.push(rule);
        Ok(())
    }

    pub(crate) fn resolve(
        &self,
        description: Option<&str>,
    ) -> Result<&RoleRule<Role>, AdmissionError> {
        let description = description.ok_or(AdmissionError::MissingDescription)?;
        self.rules
            .iter()
            .find(|rule| rule.description == description)
            .ok_or_else(|| AdmissionError::UnsupportedRole(description.into()))
    }
}
