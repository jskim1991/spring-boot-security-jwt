package io.jay.springsecurityjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jay.springsecurityjwt.authentication.rest.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.NestedServletException;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@AutoConfigureMockMvc
class SpringSecurityJwtApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    private Map<String, String> userMap;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        userMap = new HashMap<>();
        userMap.put("email", "abc@email.com");
        userMap.put("password", "simplepassword");
    }

    @Test
    void test_contextLoads() {
    }

    @Test
    void test_signup_returnsUserId() throws Exception {
        mockMvc.perform(post("/sign-up")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(mvcResult -> mvcResult.getResponse().getContentAsString().equals("1"))
        ;
    }

    @Test
    void test_loginWithNotExistingCredentials_throwsException() {
        NestedServletException exception = assertThrows(NestedServletException.class,
                () -> mockMvc.perform(post("/login")
                        .content(mapper.writeValueAsString(userMap))
                        .contentType(MediaType.APPLICATION_JSON)));
        assertThat(exception.getCause().getMessage(), equalTo("No such user for this email"));
    }

    @Test
    void test_loginWithWrongCredentialsAfterSignUp_throwsException() throws Exception {
        mockMvc.perform(post("/sign-up")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(mvcResult -> mvcResult.getResponse().getContentAsString().equals("1"));

        Map<String, String> wrongUserMap = new HashMap<>();
        wrongUserMap.put("email", "abc@email.com");
        wrongUserMap.put("password", "wrongpassword");

        NestedServletException exception = assertThrows(NestedServletException.class,
                () -> mockMvc.perform(post("/login")
                        .content(mapper.writeValueAsString(wrongUserMap))
                        .contentType(MediaType.APPLICATION_JSON)));
        assertThat(exception.getCause().getMessage(), equalTo("Wrong password"));
    }

    @Test
    void test_loginAfterSignUp_returnsToken() throws Exception {
        mockMvc.perform(post("/sign-up")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON));

        String token = mockMvc.perform(post("/login")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(token.length(), greaterThan(1));
    }

    @Test
    void test_authentication_returnsForbidden() throws Exception {
        mockMvc.perform(get("/users/hello"))
                .andExpect(status().isForbidden());
    }

    @Test
    void test_authenticationUsingAccessToken_returnsResponse() throws Exception {
        mockMvc.perform(post("/sign-up")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON));

        String tokens = mockMvc.perform(post("/login")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON))
                .andReturn()
                .getResponse()
                .getContentAsString();

        TokenResponse tokenResponse = mapper.readValue(tokens, TokenResponse.class);

        mockMvc.perform(get("/users/hello")
                .header("Authorization", "Bearer " + tokenResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", equalTo("Hello user from /users/hello")));
    }

    @Test
    void test_authenticationUsingRefreshToken_returnsResponse() throws Exception {
        mockMvc.perform(post("/sign-up")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON));

        String tokens = mockMvc.perform(post("/login")
                .content(mapper.writeValueAsString(userMap))
                .contentType(MediaType.APPLICATION_JSON))
                .andReturn()
                .getResponse()
                .getContentAsString();

        TokenResponse tokenResponse = mapper.readValue(tokens, TokenResponse.class);

        mockMvc.perform(get("/users/hello")
                .header("Authorization", "Bearer " + tokenResponse.getRefreshToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", equalTo("Hello user from /users/hello")));
    }
}
